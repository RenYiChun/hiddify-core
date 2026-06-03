package hcore

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"time"

	box "github.com/sagernet/sing-box"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	singroute "github.com/sagernet/sing-box/route"
)

func NewService(ctx context.Context, options option.Options) (*daemon.StartedService, error) {
	startedAt := time.Now()

	// ctx = filemanager.WithDefault(ctx, sWorkingPath, sTempPath, sUserID, sGroupID)
	logInterface := LogInterface{}
	bopts := daemon.ServiceOptions{
		Context:     ctx,
		Debug:       static.debug,
		LogMaxLines: 100,
		// Options:           *options,
		Handler: &logInterface,
		ExtraServices: []adapter.LifecycleService{
			&hiddifyMainServiceManager{},
		},
	}
	directLimit, proxyLimit := applyRouteConnectionAdmissionLimits(options)
	LogTiming("NewService route admission limits direct=", directLimit, " proxy=", proxyLimit)
	stageStartedAt := time.Now()
	err := libbox.CheckConfigOptions(&options)
	LogTiming("NewService CheckConfigOptions took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
	if err != nil {
		return nil, err
	}
	stageStartedAt = time.Now()
	instance := daemon.NewStartedService(bopts)
	LogTiming("NewService NewStartedService took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))

	// for i := 0; i < 10; i++ {
	// 	if hutils.IsPortInUse(options.Inbounds[0].SocksOptions.ListenPort) {
	// 		<-time.After(100 * time.Millisecond)
	// 	}
	// }

	stageStartedAt = time.Now()
	startDone := make(chan struct{})
	go func() {
		timer := time.NewTimer(15 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			LogTiming("NewService StartOrReloadServiceOptions still running after ", time.Since(stageStartedAt), ", writing goroutine-start-hang.log")
			if err := dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-start-hang.log")); err != nil {
				LogTiming("NewService goroutine-start-hang dump failed: ", err)
			}
		case <-startDone:
		}
	}()
	if err := instance.StartOrReloadServiceOptions(options); err != nil {
		close(startDone)
		LogTiming("NewService StartOrReloadServiceOptions failed after ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
		return nil, err
	}
	close(startDone)
	LogTiming("NewService StartOrReloadServiceOptions took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))

	// instance.GetInstance().AddPostService("hiddifyMainServiceManager", &hiddifyMainServiceManager{})

	// if err := startCommandServer(instance); err != nil {
	// 	return errorWrapper(MessageType_START_COMMAND_SERVER, err)
	// }

	return instance, nil
}

const (
	customRouteDirectConnectionLimitKey = "hiddify-route-direct-connection-limit"
	customRouteProxyConnectionLimitKey  = "hiddify-route-proxy-connection-limit"
)

func applyRouteConnectionAdmissionLimits(options option.Options) (directLimit int, proxyLimit int) {
	directLimit = singroute.DefaultDirectRouteConnectionAdmissionLimit
	proxyLimit = singroute.DefaultProxyRouteConnectionAdmissionLimit
	if options.Custom != nil {
		custom := *options.Custom
		directLimit = routeConnectionLimitFromCustom(custom[customRouteDirectConnectionLimitKey], directLimit)
		proxyLimit = routeConnectionLimitFromCustom(custom[customRouteProxyConnectionLimitKey], proxyLimit)
	}
	singroute.SetRouteConnectionAdmissionLimits(directLimit, proxyLimit)
	return directLimit, proxyLimit
}

func routeConnectionLimitFromCustom(value any, fallback int) int {
	if value == nil {
		return fallback
	}
	if text, ok := value.(string); ok {
		limit, err := strconv.Atoi(text)
		if err != nil || limit < 1 {
			return fallback
		}
		return normalizeRouteConnectionAdmissionLimit(limit, fallback)
	}
	reflected := reflect.ValueOf(value)
	var limit int64
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		limit = reflected.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		unsigned := reflected.Uint()
		if unsigned > uint64(^uint(0)>>1) {
			return fallback
		}
		limit = int64(unsigned)
	case reflect.Float32, reflect.Float64:
		limit = int64(reflected.Float())
	default:
		return fallback
	}
	if limit < 1 {
		return fallback
	}
	return normalizeRouteConnectionAdmissionLimit(int(limit), fallback)
}

func normalizeRouteConnectionAdmissionLimit(limit int, fallback int) int {
	if fallback == singroute.DefaultDirectRouteConnectionAdmissionLimit && limit == 512 {
		return fallback
	}
	if fallback == singroute.DefaultProxyRouteConnectionAdmissionLimit && (limit == 128 || limit == 256) {
		return fallback
	}
	return limit
}

func (h *HiddifyInstance) UrlTestHistory() *urltest.HistoryStorage {

	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.UrlTestHistory()
}

func (h *HiddifyInstance) Box() *box.Box {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Box()
}

func (h *HiddifyInstance) Instance() *daemon.Instance {
	ss := h.StartedService
	if ss == nil {
		return nil
	}
	return ss.Instance()

}

func (h *HiddifyInstance) Context() context.Context {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Context()
}

func (h *HiddifyInstance) TrafficManager() *trafficontrol.Manager {
	if ins := h.Instance(); ins != nil {
		if s := ins.ClashServer(); s != nil {
			return s.(*clashapi.Server).TrafficManager()
		}
	}
	return nil
}
