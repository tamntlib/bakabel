# Re-review R3

| Phạm vi | Verdict |
|---|---|
| **STATIC CODE** | **ĐẠT về actionable High/Medium trong source được cung cấp**: ba finding R2 đã sửa; không phát hiện hồi quy của các sửa R1. Còn **1 Low về coverage CI** bên dưới. |
| **RELEASE** | **NOT READY** — chưa đủ bằng chứng trên candidate hiện tại; **không cấp phép publish/deploy/release**. |

Review chỉ đọc source trích dẫn, **không chạy công cụ, không tính lại SHA, không xác minh image hoặc runtime receipts**. Binding được khai báo: core `6a592fcf…`, image `0b8607d9…`, PLANrev4 `ee1a05be…`. Approval người dùng chỉ áp dụng **contract C01**, không phải approval implementation.

## 1. Đóng từng finding R2

| Finding | Trạng thái | Cơ chế trong code hiện tại |
|---|---|---|
| **R2-H01 — High** | **CLOSED — static** | `internal/app/workflow.go:110–129` capture cả mount roots **và từng file thực sự được tham chiếu**: config, password, AWS credentials, notification. `internal/files/protection_linux.go:49–65` từ chối regular file có `Nlink != 1`, symlink/identity không chứng minh được; vì vậy password hard-link trong directory mount bị chặn trước `startWorkflow`. Worker vẫn kiểm physical overlap trước Restic tại `internal/files/backup_linux.go:45–51`. Config provenance nằm ở `internal/app/cli.go:27` và bị loại khỏi YAML/JSON tại `internal/config/config.go:36–37`; không thêm knob hoặc serialize nội dung bí mật. |
| **R2-M01 — Medium** | **CLOSED — static** | `internal/app/workflow_controller.go:130–135` dùng deferred fallback lấy **RunID từ handle của chính invocation**, kể cả early return do wait/cleanup lỗi; không lấy owner hiện tại để đoán identity. `internal/app/serve.go:81–86` vì thế nhận diện đúng unresolved owner và dừng scheduling. Không thay đổi generation fencing hoặc điều kiện release. |
| **R2-M02 — Medium** | **CLOSED — static** | Cả file và PG Restore gọi chung reconciliation tại `internal/app/workflow_restore.go:122–123,148–149`; Run cũng dùng helper tại `internal/app/workflow_controller.go:380–384`. Helper ở `:389–408` giữ exact handle, có cleanup budget mới 20 giây, không retry create/start và giữ lỗi launch. Cleanup vẫn phải qua terminal/source proof, exact removal và durable release; không xóa dữ liệu restore đích. |

**Regression được đọc, không coi là đã tự chạy:**

- H01: `tests/integration/fixtures/run_protected_hardlink_probe.py:24–50` dựng directory mount + hard-link cùng filesystem, yêu cầu CLI lỗi và snapshots rỗng. `internal/app/cli_config_protection_test.go:11–30` kiểm provenance không trở thành worker input/YAML knob.
- M01: `internal/app/workflow_launch_error_test.go:28–36,116–140` kiểm successful launch rồi outage; nhánh Serve yêu cầu đúng một identified result và blocked.
- M02: `internal/app/workflow_restore_launch_test.go:26–64,173–193` bao phủ hai loại restore × create/start loss × terminal/unavailable proof; kiểm đã tới launch, không retry, giữ owner khi chưa có proof. Đây là **Engine seam**, không phải real-daemon import-loss acceptance.

## 2. Audit các sửa R1

| Finding | Trạng thái R3 và cơ sở |
|---|---|
| **R1-H01** | **CLOSED — static**, nhờ closure R2-H01 ở trên; không tính thêm một High. |
| **R1-H02** | **CLOSED, không thấy hồi quy** — `internal/app/workflow_controller.go:149–170,228–265`: waiter truyền expected generation; kiểm daemon/run/name/established ID trước thao tác và sau lấy guard. |
| **R1-M01** | **CLOSED** — `internal/app/workflow_restore.go:162–189`; `internal/platform/docker/restore_postgres.go:110–125`: creating-intent chỉ được persist tại boundary trước POST create, sau read-only checks. |
| **R1-M02** | **CLOSED trong public workflow** — `internal/app/workflow_controller.go:266–277,360–366`: persist adopted ID trước discard; remove/readback trước release. `internal/platform/docker/worker.go:49–55,94–98` và `worker_remove.go:12–24` giữ exact-ID/name absence proof. |
| **R1-M03** | **CLOSED** — `internal/platform/docker/client.go:30–38` có finite idle timeout và explicit Close. Các lifetime production vẫn đóng client, gồm helper mới tại `internal/app/workflow_controller.go:399–404`. |
| **R1-M04** | **CLOSED** — `internal/app/workflow_restore.go:141`; `internal/restore/postgres.go:39–62`: shared normalized ACL comparison vẫn giữ owner, grantor, grantee, privilege và grant option. |
| **R1-M05** | **CLOSED** — `internal/backup/metadata.go:162–174`; `internal/backup/metadata_json.go:19–69`: duplicate-key rejection trước typed decode, gồm escaped/case-folded keys, nested objects, depth và trailing value. |
| **R1-M06** | **CLOSED**, nay bao phủ cả thiếu sót R2-M01/M02 — `internal/app/workflow_controller.go:389–408`; `internal/app/serve.go:81–86`. |
| **R1-M07** | **CLOSED** — `internal/app/health.go:39,75–78`: trạng thái hiển thị `running` không xóa `lastFailed` khỏi quyết định exit status. |
| **R1-C01** | **CLOSED — contract được duyệt** — `PLAN.md:116–118,299`; Compose `internal/platform/docker/discovery.go:123,139–157` xét cả stopped metadata; Swarm `discovery_swarm.go:76–95` vẫn fail khi không có running task hợp lệ. |
| **R1-L02** | **CLOSED — tài liệu** — `README.md:5`, `docs/restore.md:43`, `docs/resources.md:7–9,49` phân biệt historical baseline và candidate; không đổi AppArmor failure thành PASS. |

**R1-L01 vẫn optional/deferred:** `internal/app/helper.go:21–22`, `internal/app/worker.go:160–326`. Không yêu cầu xóa B1 lifecycle trước khi chuyển đủ safety evidence sang public workflow.

## 3. Finding mới

### R3-L01 — Low · CI hiện tại luôn skip regression tám nhánh public Restore

**Vị trí chính xác:**

- `.github/workflows/ci.yaml:51–55`
- `internal/app/workflow_restore_launch_test.go:26–29`

**Cơ chế:** CI đặt `RESTIC_TEST_BINARY=/probe/restic` và mount binary tại đó, nhưng test mới chỉ chạy khi biến này **bằng `/usr/bin/restic`**. Vì vậy bước `go test -race ./...` hiện tại luôn skip regression R2-M02, dù đã chuẩn bị Restic thật. Dedicated local run được báo PASS không sửa coverage của workflow CI.

**Sửa nhỏ nhất:** trong container Go của bước CI, mount Restic tại `/usr/bin/restic` và đặt `RESTIC_TEST_BINARY` cùng đường đó; hoặc thêm một bước riêng chạy test này với đúng production path. Giữ nguyên production binary path.

**Xác nhận cần có:** CI output phải thể hiện tám subcases thực sự chạy, không `SKIP`. Đây là lỗi coverage CI, **không mở lại closure static R2-M02**.

## 4. Counts

| Nhóm còn mở | High | Medium | Low |
|---|---:|---:|---:|
| Actionable production Go | **0** | **0** | **0** |
| Actionable test/CI | **0** | **0** | **1** |
| Contract chưa quyết định | **0** | **0** | **0** |
| Optional/deferred — R1-L01 | **0** | **0** | **1** |

- **R2: 3/3 CLOSED ở mức static.**
- **11 mục R1 bắt buộc đối chiếu: 11 CLOSED**, phân biệt closure code, contract và tài liệu như bảng trên.
- Release/evidence gates **không cộng vào số lỗi code High/Medium**.

## 5. Release gates vẫn độc lập

1. Đọc và verify receipts **đã hoàn tất**, binding đúng R3, cho Compose/local+S3, alias/hard-link, ACL, scheduler/resources và OOM/ENOSPC. “Đã launch” chưa phải PASS.
2. Full current-candidate **Swarm và file-restore replay** trên disposable daemon được hỗ trợ, toàn bộ consumer backing storage trong scope.
3. Hoàn tất **B1 → public workflow fault mapping**, gồm các real-daemon scheduled launch-loss/import-loss còn thiếu. Không nâng Engine seam thành bằng chứng lỗi mạng/import thật.
4. Giữ rõ resource boundaries: configured-32-MiB **early OOM** không chứng minh active-export/during-stream OOM; large-index RAM, physical I/O, affinity liên tục từ process birth và large-data RTO vẫn chưa được chứng minh.
5. Hosted CI và provenance của candidate vẫn cần xác minh riêng.

Đã đọc bốn runner được cung cấp, nhưng **không suy rằng base harness/verifier bị lược bỏ đã được review**; tương tự với omitted Go tests, raw artifacts và image contents. Worker old-image không được bảo vệ hồi tố.

**Kết luận:** các sửa R2 là sửa code cụ thể, giữ nguyên fail-closed và dùng chung lifecycle thay vì nhân đôi logic. **Không còn actionable High/Medium được xác định trong source supplied; release vẫn NOT READY và không được tự động phê duyệt.**
