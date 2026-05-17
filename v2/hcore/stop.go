package hcore

import (
	"context"
	"fmt"
	"time"

	"github.com/hiddify/hiddify-core/v2/config"
	hcommon "github.com/hiddify/hiddify-core/v2/hcommon"
)

func (s *CoreService) Stop(ctx context.Context, empty *hcommon.Empty) (*CoreInfoResponse, error) {
	return Stop()
}

func Stop() (coreResponse *CoreInfoResponse, err error) {
	startedAt := time.Now()
	defer config.DeferPanicToError("stop", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})

	// if static.CoreState != CoreStates_STARTED {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_STARTED, fmt.Errorf("instance not started"))
	// }
	// if static.Box == nil {
	// 	return errorWrapper(MessageType_INSTANCE_NOT_FOUND, fmt.Errorf("instance not found"))
	// }
	static.lock.Lock()
	defer static.lock.Unlock()
	LogTiming("StopService begin")

	SetCoreStatus(CoreStates_STOPPING, MessageType_EMPTY, "")
	ss := static.StartedService
	if ss == nil {
		response := SetCoreStatus(CoreStates_STOPPED, MessageType_ALREADY_STOPPED, "")
		LogTiming("StopService already stopped in ", time.Since(startedAt))
		return response, nil
	}

	stageStartedAt := time.Now()
	if err := ss.CloseService(); err != nil {
		LogTiming("StopService CloseService failed after ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
		static.StartedService = nil
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-stop.log"))
		return errorWrapper(MessageType_UNEXPECTED_ERROR, err)
	}
	LogTiming("StopService CloseService took ", time.Since(stageStartedAt), " total ", time.Since(startedAt))
	// err = common.Close(static.StartedService)
	static.StartedService = nil

	response := SetCoreStatus(CoreStates_STOPPED, MessageType_EMPTY, "")
	LogTiming("StopService finished in ", time.Since(startedAt))
	return response, nil
}
