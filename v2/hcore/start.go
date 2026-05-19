package hcore

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	"github.com/hiddify/hiddify-core/v2/db"
	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
	service_manager "github.com/hiddify/hiddify-core/v2/service_manager"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func (s *CoreService) Start(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return Start(static.BaseContext, in)
}

func Start(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return StartService(ctx, in)
}

func (s *CoreService) StartService(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return StartService(ctx, in)
}

func saveLastStartRequest(in *StartRequest) error {
	if in.ConfigContent == "" && in.ConfigPath == "" {
		return nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	return settings.UpdateInsert(
		&hcommon.AppSettings{
			Id:    "lastStartRequestPath",
			Value: in.ConfigPath,
		},
		&hcommon.AppSettings{
			Id:    "lastStartRequestContent",
			Value: in.ConfigContent,
		},
		&hcommon.AppSettings{
			Id:    "lastStartRequestName",
			Value: in.ConfigName,
		},
	)
}

func loadLastStartRequestIfNeeded(in *StartRequest) (*StartRequest, error) {
	if in != nil && (in.ConfigContent != "" || in.ConfigPath != "") {
		return in, nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	lastPath, err := settings.Get("lastStartRequestPath")
	if err != nil {
		return nil, err
	}
	lastContent, err := settings.Get("lastStartRequestContent")
	if err != nil {
		return nil, err
	}

	lastName, err := settings.Get("lastStartRequestName")
	if err != nil {
		return nil, err
	}
	return &StartRequest{
		ConfigPath:    lastPath.Value.(string),
		ConfigContent: lastContent.Value.(string),
		ConfigName:    lastName.Value.(string),
	}, nil
}

func StartService(ctx context.Context, in *StartRequest) (coreResponse *CoreInfoResponse, err error) {
	startedAt := time.Now()
	defer config.DeferPanicToError("startmobile", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})
	static.lock.Lock()
	defer static.lock.Unlock()
	LogTiming("StartService begin")

	if static.CoreState != CoreStates_STOPPED {
		// return errorWrapper(MessageType_ALREADY_STARTED, fmt.Errorf("instance already started"))
		return &CoreInfoResponse{
			CoreState:   static.CoreState,
			MessageType: MessageType_ALREADY_STARTED,
			Message:     "instance already started",
		}, nil
	}
	SetCoreStatus(CoreStates_STARTING, MessageType_EMPTY, "")

	in, err = loadLastStartRequestIfNeeded(in)
	if err != nil {
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}

	static.previousStartRequest = in
	stageStartedAt := time.Now()
	options, err := BuildConfig(ctx, in)
	if err != nil {
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}
	LogTiming("StartService BuildConfig took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
	saveLastStartRequest(in)

	stageStartedAt = time.Now()
	Log(LogLevel_DEBUG, LogType_CORE, "Main Service pre start")
	if err := service_manager.OnMainServicePreStart(options); err != nil {
		return errorWrapper(MessageType_ERROR_EXTENSION, err)
	}
	LogTiming("StartService OnMainServicePreStart took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
	currentBuildConfigPath := filepath.Join(sWorkingPath, "data/current-config.json")
	Log(LogLevel_DEBUG, LogType_CORE, "Saving config to ", currentBuildConfigPath)

	stageStartedAt = time.Now()
	config.SaveCurrentConfig(ctx, currentBuildConfigPath, *options)
	LogTiming("StartService SaveCurrentConfig took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
	if static.debug {
		pout, err := options.MarshalJSONContext(ctx)
		if err != nil {
			return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
		}
		Log(LogLevel_INFO, LogType_CORE, "Current Config is:\n", string(pout))
	}
	ctx = libbox.FromContext(ctx, static.globalPlatformInterface)
	if static.globalPlatformInterface != nil {
		platformWrapper := libbox.WrapPlatformInterface(static.globalPlatformInterface)
		service.MustRegister[adapter.PlatformInterface](ctx, platformWrapper)
		// } else {
		// 	service.MustRegister[adapter.PlatformInterface](ctx, (*adapter.PlatformInterface)nil)
	}
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service with delay ?", in.DelayStart)
	if in.DelayStart {
		<-time.After(1000 * time.Millisecond)
	}
	libbox.SetMemoryLimit(C.IsIos || !in.DisableMemoryLimit)
	startDynamicDirectBypassIfNeeded(*options)
	stageStartedAt = time.Now()
	instance, err := NewService(ctx, *options)
	LogTiming("StartService NewService took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
	if err != nil {
		stopDynamicDirectBypass(context.Background())
		return errorWrapper(MessageType_START_SERVICE, err)
	}
	static.StartedService = instance
	if static.debug {
		dumpPath := fmt.Sprint(sWorkingPath, "/data/goroutine-start.log")
		go func() {
			dumpStartedAt := time.Now()
			if err := dumpGoroutinesToFile(dumpPath); err != nil {
				LogTiming("StartService goroutine dump failed after ", time.Since(dumpStartedAt), ": ", err)
				return
			}
			LogTiming("StartService goroutine dump took ", time.Since(dumpStartedAt))
		}()
	}
	for inb := range options.Inbounds {
		if opts, ok := options.Inbounds[inb].Options.(option.SocksInboundOptions); ok {
			static.ListenPort = opts.ListenPort
		}
	}

	response := SetCoreStatus(CoreStates_STARTED, MessageType_EMPTY, "")
	go func() {
		time.Sleep(200 * time.Millisecond)
		if _, err := static.UrlTestActive(); err != nil {
			Log(LogLevel_WARNING, LogType_CORE, "StartService active URL test failed: ", err)
			return
		}
		Log(LogLevel_INFO, LogType_CORE, "StartService active URL test queued")
	}()
	go refreshEmbeddedRuleSetFilesWithRetry()
	LogTiming("StartService finished in ", time.Since(startedAt))
	return response, nil
}
