#ifndef INTEGRITY_MONITOR_TRACE_H
#define INTEGRITY_MONITOR_TRACE_H

#define MONITOR_DBG_PRINT(level, msg, ...) \
    DbgPrint("[IntegrityMonitor] " msg, __VA_ARGS__)

#define MONITOR_LOG_PROCESS(pid, name, action) \
    MONITOR_DBG_PRINT(0, "[PROCESS] %s - PID: %lu - %wZ\n", action, pid, name)

#define MONITOR_LOG_IMAGE(pid, path) \
    MONITOR_DBG_PRINT(0, "[IMAGE] PID: %lu loaded: %wZ\n", pid, path)

#define MONITOR_LOG_HANDLE(pid, target, access) \
    MONITOR_DBG_PRINT(0, "[HANDLE] PID: %lu -> PID: %lu access: 0x%X\n", pid, target, access)

#endif
