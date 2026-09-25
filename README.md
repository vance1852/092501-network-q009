# 城市地下管网安全监测与应急调度服务

本项目为城市供水、排水和燃气管网提供离线后台服务，保存管段、传感器读数、泄漏告警、巡检工单、维修审批和应急资源分配。系统使用确定性的风险评分帮助值班人员优先处理高风险管段，账号按角色授予读取、处置和审批权限，状态变化写入 SQLite 审计表。

## 目录

- `src/urban_network/`：管网领域服务、风险计算、权限、SQLite 存储和 JSON API；
- `src/power_dispatch/`：应急泵站资源分配使用的计划与容量计算组件；
- `src/plant_science/`：传感器校准与统计分析组件；
- `tests/`：领域规则、存储事务和 API 测试。

## 环境

- Linux
- Python 3.11 或更高版本
- 运行时仅使用 Python 标准库和 SQLite

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -q
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m urban_network.acceptance --workspace .
```

验收命令会创建演示管段、导入传感器读数、计算泄漏风险、生成巡检工单并输出 JSON。它不访问外部网络，也不要求常驻的数据库、队列或其他服务。

## HTTP API

```bash
PYTHONPATH=src python3 -m urban_network.api --database network.sqlite3 --host 127.0.0.1 --port 8080
```

`GET /health` 返回服务状态，其余接口使用 JSON 和 `Authorization: Bearer <token>` 会话，支持管段登记、读数上报、风险查询、工单创建和应急资源分配。

## 告警去重与合并

读数的观测时刻在上报时统一规范化为 UTC，告警指纹由稳定的读数身份（管段、传感器、规范化时刻）和异常类型构成，因此同一时刻的不同时区写法（如网关本地偏移与中心节点 UTC 重传）只生成一条告警。同一管段、传感器和异常类型在去重窗口内（默认 3600 秒，可用 `NetworkService(dedup_window_seconds=...)` 调整）的重复事件会合并到未结告警：保留首次与末次出现时刻、重复次数和全部来源读数编号；窗口之外的新异常独立成案。乱序重放与并发上报在事务和锁的保护下不会产生重复告警，对同一告警的重复派单会返回已有工单。风险报告携带每条告警的指纹、异常类型、首末时刻、重复次数、来源列表及去重窗口，合并过程写入审计事件（`alert` 实体的 `created`/`merged`），可通过审计接口查询合并依据。
