from typing import Any, Dict, List


def _get_nested(d: Dict[str, Any], key: str) -> Any:
    cur: Any = d
    for part in key.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _first(d: Dict[str, Any], keys: List[str]) -> Any:
    for k in keys:
        v = _get_nested(d, k)
        if v is not None:
            return v
    return None


def normalize_event(event: Dict[str, Any]) -> Dict[str, Any]:
    e = dict(event)

    cmd = _first(e, [
        'CommandLine', 'command_line', 'commandLine', 'cmdline',
        'process.command_line', 'process.commandLine', 'payload', 'args', 'arguments', 'cli',
        'message'
    ])
    img = _first(e, [
        'Image', 'image', 'process.executable', 'process.image', 'exe', 'file.path', 'path',
        'process.name', 'binary', 'program', 'process.file.name'
    ])
    parent_img = _first(e, [
        'ParentImage', 'parent.image', 'ppid.image', 'process.parent.executable', 'process.parent.image'
    ])
    parent_cmd = _first(e, [
        'ParentCommandLine', 'parent.command_line', 'process.parent.command_line'
    ])
    msg = _first(e, ['Message', 'message', 'log', 'msg'])
    evt_id = _first(e, [
        'EventID', 'event.code', 'winlog.event_id', 'eventId', 'event_id', 'sysmon.event_id', 'id'
    ])
    user = _first(e, [
        'User', 'user.name', 'username', 'account', 'actor.user.name', 'subject', 'user'
    ])
    host = _first(e, ['Host', 'host.name', 'hostname', 'computer_name'])
    src_ip = _first(e, ['SourceIp', 'source.ip', 'src_ip', 'sourceIPAddress'])
    dst_ip = _first(e, ['DestinationIp', 'destination.ip', 'dst_ip'])
    src_port = _first(e, ['SourcePort', 'source.port', 'src_port'])
    dst_port = _first(e, ['DestinationPort', 'destination.port', 'dst_port'])
    reg_path = _first(e, ['RegistryPath', 'registry.path', 'reg.path'])

    cloud_evt = _first(e, ['eventName', 'OperationName'])
    cloud_src = _first(e, ['eventSource', 'EventSource'])

    if cmd is not None and 'CommandLine' not in e:
        e['CommandLine'] = cmd
    if img is not None and 'Image' not in e:
        e['Image'] = img
    if parent_img is not None and 'ParentImage' not in e:
        e['ParentImage'] = parent_img
    if parent_cmd is not None and 'ParentCommandLine' not in e:
        e['ParentCommandLine'] = parent_cmd
    if msg is not None and 'message' not in e:
        e['message'] = msg
    if evt_id is not None and 'EventID' not in e:
        e['EventID'] = evt_id
    if user is not None and 'User' not in e:
        e['User'] = user
    if host is not None and 'Host' not in e:
        e['Host'] = host
    if src_ip is not None and 'SourceIp' not in e:
        e['SourceIp'] = src_ip
    if dst_ip is not None and 'DestinationIp' not in e:
        e['DestinationIp'] = dst_ip
    if src_port is not None and 'SourcePort' not in e:
        e['SourcePort'] = src_port
    if dst_port is not None and 'DestinationPort' not in e:
        e['DestinationPort'] = dst_port
    if reg_path is not None and 'RegistryPath' not in e:
        e['RegistryPath'] = reg_path
    if cloud_evt is not None and 'EventName' not in e:
        e['EventName'] = cloud_evt
    if cloud_src is not None and 'EventSource' not in e:
        e['EventSource'] = cloud_src

    return e


def normalize_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_event(ev) for ev in events]