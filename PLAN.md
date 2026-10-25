# Bakabel — Implementation Plan

Trạng thái: revision 4, làm rõ contract Compose theo quyết định người dùng cho R1-C01 của implementation review. Implementation đang được sửa và kiểm chứng; chưa tạo remote repository, chưa publish hoặc deploy. Approval của các review plan trước không thay cho approval implementation.

## 1. Mục tiêu và giới hạn

Bakabel là công cụ backup theo metadata, viết bằng Go, dùng Restic làm engine repository. Không dùng hoặc fork stack-back. Ưu tiên ít code, ít tiến trình, thấp CPU/RAM/đĩa và hoạt động đúng khi lỗi.

- Tên repo/binary: `bakabel`; remote dự kiến `tamntlib/bakabel`.
- Image dự kiến: `ghcr.io/tamntlib/bakabel`, chưa xuất bản.
- MVP hỗ trợ Docker Compose và Docker Swarm; Kubernetes là giai đoạn sau.
- Backup PostgreSQL online và backup file từ các mount được chọn; S3-compatible hoặc local repository.
- Một platform được cấu hình rõ ràng, một lịch chung, một repository, xử lý tuần tự.
- Project/stack backup độc lập: cập nhật Bakabel không redeploy ứng dụng.
- Không stop, restart hoặc scale-down ứng dụng trong backup; không có offline fallback.
- Không có UI, HTTP API, Redis, database server, queue, plugin framework hoặc code Kubernetes dựng trước.
- Swarm MVP chỉ hỗ trợ target trên cùng manager/node/daemon với Bakabel. Target trên node khác phải báo unsupported placement, không bỏ qua hoặc đoán volume.
- Nhiều replica chưa có quy tắc chọn nguồn được kiểm chứng: báo lỗi; không tự backup trùng hoặc chọn primary bằng suy đoán.
- Chưa có PITR/WAL, whole-cluster PostgreSQL, restore đè hoặc tự chuyển traffic.

Đây là kế hoạch, không phải cam kết các chức năng đã tồn tại. Tạo file này không cấp phép tạo GitHub repo, publish image, đọc bí mật, backup dữ liệu thật hoặc deploy.

## 2. Kiến trúc tối giản

```text
serve: scheduler Go chờ tới lịch
  -> cùng pipeline của run
     -> discovery + validation -> kế hoạch target cố định
     -> khóa thực thi -> một worker tạm
        -> từng target: PostgreSQL export hoặc đọc volume
        -> Restic -> S3/local
        -> kết quả -> dọn worker/tài nguyên tạm thuộc lượt chạy
```

- Chỉ discovery khi bắt đầu lượt chạy; không watch Docker events hoặc quét inventory liên tục.
- Scheduler và worker cùng image; worker chỉ tồn tại khi làm việc.
- Go binary dùng timer chờ, không busy loop. Cron parser phải hỗ trợ cú pháp được công bố, có timezone, sai lịch phải fail startup thay vì đổi về mặc định.
- Chỉ giữ state nhỏ cho lượt đang chạy và kết quả gần nhất; ghi nguyên tử. Không lưu lịch sử job vô hạn.
- Hai ranh giới code: backup core và platform. Không làm framework/plugin registry.
- Compose và Swarm chia sẻ inspect/exec/mount/worker lifecycle qua Docker Engine API; chỉ discovery khác nhau.
- Không đặt điều kiện theo tên component/service cụ thể trong core.

Bố cục dự kiến, chỉ tạo thư mục khi có code thực:

```text
cmd/bakabel/
internal/config/
internal/platform/docker/   # Compose/Swarm discovery + Docker execution
internal/backup/            # pipeline postgres/files và Restic adapter
internal/state/            # lock/result tối thiểu
deploy/                    # Compose/Swarm examples, không dữ liệu riêng
tests/integration/
docs/
Dockerfile
```

## 3. Khai báo nguồn — labels tối thiểu

| Label | Hành vi đề xuất |
|---|---|
| `bakabel.type=postgres` | Opt-in dump PostgreSQL |
| `bakabel.type=volume` | Opt-in sao chép file của các mount được chọn |
| `bakabel.paths=/data` | Bắt buộc cho volume; đường mount trong container, có thể danh sách được validate |
| `bakabel.postgres.database=app` | Optional override; thiếu thì đọc POSTGRES_DB từ container nguồn; không xác định được thì báo lỗi |

- Không có `bakabel.enable`: type đã là opt-in.
- Không có `bakabel.consistency`, cờ xác nhận thay thế hoặc label offline/stop.
- Không có policy/schedule riêng theo nguồn trong MVP.
- Không cho phép password/token, shell command, hook tùy ý hoặc image worker tùy ý qua labels.
- PostgreSQL user đọc từ cấu hình container theo adapter; thiếu hoặc không dùng được thì báo lỗi thay vì đoán. Authentication không được xuất ra log; hỗ trợ credential references khi cần được chốt bằng test.
- Không suy loại database từ tên image để tự bật backup. Không có type thì không chọn; type không hợp lệ phải báo lỗi.

Compose đọc `services.<service>.labels`, dựa trên metadata project/service Docker Compose. Swarm đọc `services.<service>.deploy.labels`, resolve service -> running task -> node/container. Không cần đọc file Compose tại runtime.

Ví dụ hai trường hợp riêng, không phải manifest ứng dụng hoàn chỉnh:

```yaml
# Compose PostgreSQL: services.db
labels:
  bakabel.type: postgres
```

```yaml
# Swarm files: services.files
deploy:
  labels:
    bakabel.type: volume
    bakabel.paths: /data
```

`type=volume` chỉ có nghĩa là sao chép file; không hứa point-in-time hoặc application consistency. Nguồn database đang ghi cần adapter riêng. Không thể tự phát hiện tất cả định dạng DB; docs phải nói rõ giới hạn này, không tái tạo cờ consistency để giả làm bằng chứng.

## 4. Cấu hình chung và quyền truy cập

Một `bakabel.yaml` quản lý platform, phạm vi project/stack được phép discovery, lịch/timezone, Restic repository, references tới credentials, timeout và tùy chọn vận hành cần thiết. Không có danh sách service/volume/mount tập trung.

- Dùng một Restic repository URL, không xây hai storage engine S3/local hoặc cấu hình backend trùng với URL.
- S3: endpoint/bucket/prefix qua repository URL; region và credential files theo nhu cầu provider. TLS verification không bị tắt mặc định.
- Local: mount repository persistent tại một đường cố định; không lưu trong writable layer của container tạm.
- State/cache có đường mặc định, chỉ mở override khi có nhu cầu thực. Scheduler và worker phải dùng đúng đường trên đúng daemon.
- Thiết kế cách cấp credential files cho worker phải rõ và được thử thật: container tạo qua Docker API không mặc nhiên kế thừa Swarm Secret mounts. Không tự chuyển secrets vào labels/argv/log hoặc Docker Config.Env vì tiện.
- Worker chỉ có source mounts read-only; repository/cache/state/temp chỉ writable nơi cần. Inspect mount permissions phải được giữ đúng, không biến mọi mount thành rw.
- Không tự backup Docker socket, secret/config mounts, repository, cache hoặc state của Bakabel. Resolve nguồn bằng mount được inspect; không tạo volume mới chỉ vì thiếu tên nguồn.
- Docker socket cấp quyền mạnh dù bind mount là `:ro`; tài liệu phải giải thích. Không cần public network hoặc port web.
- Restore trên máy mới chỉ cần access repository, khóa giải mã và credentials/đích restore; không phụ thuộc container nguồn hoặc state scheduler còn tồn tại.
- Để đơn giản hóa khóa, MVP hỗ trợ một installation/scheduler sở hữu một repository; không tuyên bố distributed coordination giữa các installation độc lập. Restic locks vẫn được giữ.

## 5. Backup pipeline và ngân sách đĩa

### 5.1 Discovery/validation

Mỗi lượt tạo tập target cố định và stable source ID gồm installation scope + Compose project/service hoặc Swarm stack/service + mount/database. Không dùng container/task ID làm identity của snapshot. Resolve runtime ID cho lượt chạy, kiểm tra lại trước thao tác. Task/container thay thế hoặc mount drift phải fail target rõ ràng, không tự đổi nguồn giữa lượt.

Logical source ID phục vụ grouping, không phải bằng chứng identity vật lý. Kế hoạch và metadata snapshot cần fingerprint nguồn có thể kiểm tra khi restore: PostgreSQL cluster system identifier + database OID; file/volume có daemon/node scope, mount identity và thông tin backing storage đã resolve. Nếu không đọc được identity đáng tin cậy thì target chưa được hỗ trợ, không hạ xuống so hostname/tên database/tên volume. Clone giữ nguyên fingerprint được xử lý bảo thủ, không tự suy ra đó là nguồn khác.

Compose: service được đánh dấu còn ít nhất một container metadata quan sát được phải báo lỗi nếu không chạy hoặc không xác định được nguồn duy nhất; list phải bao gồm cả container đã dừng. Khi container cuối cùng của một service bị xoá, Docker Engine không còn Compose service object/labels: thiết kế stateless không cam kết phát hiện service đã mất toàn bộ metadata hoặc chứng minh coverage của một desired-service inventory. Không thêm registry nguồn, runtime dependency vào file Compose hoặc event watcher để suy đoán điều đó.

Swarm: service object được đánh dấu còn tồn tại nhưng không có task chạy, hoặc thiếu quyền/nguồn/placement, phải báo lỗi thay vì biến mất khỏi báo cáo. Không có nguồn là kết quả riêng, không làm mới last-success của một lượt backup dữ liệu. Một lượt complete chỉ chứng nhận tập target đã discovery và cố định của lượt đó, không tự chứng nhận mọi service ứng dụng dự kiến đều được bao phủ.

### 5.2 PostgreSQL — ưu tiên streaming an toàn

Thiết kế trước dùng dump -> staging file -> upload. Yêu cầu ít chiếm đĩa thay hướng ưu tiên thành:

```text
pg_dump custom-format trong container nguồn
 -> Docker exec stream, stdout/stderr tách biệt
 -> helper nội bộ Bakabel trả đúng exec exit status
 -> restic backup --stdin-from-command
 -> repository
```

- Không dùng pipe `--stdin` thông thường rồi chỉ kiểm tra exit của Restic.
- Helper là hành vi cố định trong binary, không chạy shell command do label cung cấp.
- Dùng buffer giới hạn và backpressure; không giữ toàn dump trong RAM hoặc ghi bản dump local mặc định.
- Phải lấy được trạng thái kết thúc Docker exec; missing/unknown/nonzero là lỗi. Stderr không đi vào nội dung dump và phải được lọc bí mật.
- Restic có cơ chế `--stdin-from-command` hủy snapshot khi command nguồn lỗi. Đây mới là bằng chứng tài liệu; đường Docker helper phải được kiểm chứng end-to-end trước khi chốt MVP. Không tự thêm staging fallback/mode mới nếu spike không đạt; báo blocker và hỏi người dùng.
- Upload lỗi, nguồn chết, timeout, cancellation phải dừng/thu hồi đúng helper/exec, không để pg_dump tiếp tục ngoài giám sát. Kiểm chứng bằng failure probes, không chỉ mock.
- **Cancellation là gate B1, không chờ đến scheduler B4.** Docker client disconnect, helper chết hoặc worker SIGKILL không chứng minh source exec đã kết thúc; dump chờ lock có thể chưa ghi stdout để gặp broken pipe.
- Trước exec_start phải lưu đủ source container ID, exec ID và run identity vào state sở hữu lượt; mọi khoảng gián đoạn giữa create/persist/start được test. B1 phải chọn một cơ chế hủy export chính xác trên image nguồn hỗ trợ và chứng minh quyền/công cụ cần thiết. Không kill container, không pkill theo tên và không signal PID chưa kiểm chứng identity/start time. Không thêm agent source thường trực hoặc helper mới trong image nguồn chỉ để vượt gate mà chưa xin quyết định.
- Sau hủy, phải xác nhận exec thực sự kết thúc và không còn export/session thuộc lượt đang chạy; khóa bao phủ cả worker lẫn export nguồn. Mất khả năng inspect, identity mơ hồ hoặc exec còn sống thì ghi blocked, giữ ownership/quarantine qua scheduler restart, không nhả khóa để chạy lượt mới. Chỉ release sau bằng chứng terminal hoặc source container cũ đã thực sự kết thúc/không còn trên đúng daemon; không nhầm container thay thế.
- B1 bắt buộc thử worker SIGKILL khi dump chờ lock, nguồn đang stream, Docker disconnect và scheduler restart. Nếu không chứng minh cancellation/recovery trong phạm vi nguồn MVP thì B1 BLOCKED; không tự đổi sang staging hoặc nới acceptance.
- Một database một export. Không tuyên bố roles/globals hoặc đồng bộ nhất quán nhiều DB/volume.
- Snapshot lỗi không được báo thành công. Block đã upload trước lỗi có thể còn trong repository, dù không có snapshot; không hứa lỗi không chiếm dung lượng remote.
- Client dump chạy trong container nguồn nên CPU/RAM/I/O tại DB cũng phải được đo; worker cgroup limit không tự giới hạn Docker exec trong DB container.

### 5.3 File/volume

Source mount read-only -> Restic đọc file trực tiếp. Không tar/copy cả volume ra staging trước. `paths` phải match các mount hợp lệ, không cho traversal hoặc broaden sang host path tùy ý. Nếu file không đọc được hoặc Restic trả partial/error, target và lượt chạy không được coi là thành công đầy đủ.

Đường đọc trong worker ổn định theo source ID + mount path, không chứa run/container/task ID. Restic nhận hostname ổn định của installation và grouping `host,paths` cố định cho backup lẫn retention; không dùng hostname ngẫu nhiên của worker. Chọn một convention nội bộ, không thêm knob. Hai lượt file backup không đổi phải chứng minh parent được chọn đúng và không đọc lại toàn bộ content chỉ vì worker thay mới.

### 5.4 Metadata phục hồi và kết quả

Snapshot phải mang metadata phiên bản, source ID, loại nguồn, layout/path; với PostgreSQL thêm DB name, server/client version và custom dump format. Không chứa credentials. Metadata phải gắn với đúng snapshot, không dựa vào newest file hoặc state local tách rời.

Handoff PostgreSQL phải phân biệt object ownership/ACL với owner/ACL **cấp database**. Metadata cùng snapshot ghi tên database owner và database ACL đã chuẩn hóa theo role name, gồm PUBLIC, privilege và grant option; ACL NULL phải được diễn giải theo default PostgreSQL, không coi là không có quyền. Không dùng role OID để so giữa hai cluster, không lưu role password hoặc toàn bộ globals. Đây là prerequisite reference để operator chuẩn bị đích; không có tính năng tự apply GRANT/REVOKE/ALTER DATABASE trong MVP.

MVP chọn metadata nhỏ versioned qua Restic tags và layout/path ổn định, không thêm manifest file vào command streaming. Metadata phải ghi rõ exact dump path, format version, source identity/fingerprint, loại nguồn và thông tin PostgreSQL cần thiết. Encoding/escaping và size limits được chốt/test ở B1; metadata thiếu, mâu thuẫn hoặc version không hỗ trợ không được coi là hợp lệ. Không upload hai snapshot độc lập rồi coi cặp đó atomic; không dựng catalog database.

Trạng thái **complete/partial/unknown nằm trong repository**, không chỉ state local:

- Mọi snapshot ban đầu mang status `unknown`, run/target identity; không gắn complete khi bắt đầu backup.
- Chỉ sau Restic exit 0 và xác minh nguồn export kết thúc thành công mới finalize đúng snapshot thành `complete`, rồi read back status và metadata. Restic exit 3 có thể đã tạo snapshot: ghi cả snapshot ID lẫn lỗi và finalize `partial` nếu làm được; không finalize được thì giữ unknown.
- Finalize tag có thể thay snapshot ID. Theo dõi chính xác mapping old/new và read back bằng run/target identity, không chọn snapshot mới nhất. Receipt trả final ID. B1 phải thử hành vi version Restic đã pin thay vì giả định tag mutation giữ ID.
- Crash giữa commit/finalize/report để lại unknown hoặc complete đã được xác minh theo bước tương ứng; môi trường mới phải phân loại được bằng repository. Metadata/trạng thái không rõ là unknown, không tự nâng thành complete từ sự tồn tại snapshot.
- `snapshots` luôn hiển thị status. `restore` MVP chỉ nhận complete với metadata hợp lệ; từ chối partial/unknown, không thêm force flag. Salvage qua Restic thủ công là thao tác operator ngoài contract Bakabel.

Kết quả target chứa status, snapshot ID nếu có **và** lỗi nếu có; hai trường không loại trừ nhau. Lượt tổng chỉ thành công khi mọi target bắt buộc complete. Các snapshot complete của target trước có thể vẫn tồn tại khi target sau lỗi; không tuyên bố toàn lượt atomic. Finalization error không bị che thành backup thành công; housekeeping không tự prune unknown/partial để làm sạch báo cáo.

## 6. Restore là chức năng MVP

Giao diện người dùng dự kiến: `plan`, `run`, `serve`, `snapshots`, `restore`. `worker` và helper export là nội bộ. Không xây UI/browser repository. `restic check` và quản trị thấp hơn vẫn dùng Restic trực tiếp.

- `plan`: discovery/validation chỉ đọc, không tạo worker, init repository hoặc upload.
- `run`: một lượt rồi thoát; `serve` chờ lịch và gọi cùng pipeline.
- `snapshots`: liệt kê source/type/time/status và snapshot ID từ metadata repository, hoạt động khi mất state/source.
- `restore`: bắt buộc chỉ định snapshot ID complete có metadata hợp lệ và đích rõ ràng; không tự chọn latest hoặc source hiện tại làm đích.

### PostgreSQL restore

Restic lấy đúng dump -> `pg_restore` vào DB mới/rỗng được chỉ định -> kiểm tra tất cả exit status -> báo kết quả import. Ưu tiên tránh full-file staging nếu custom-format sequential restore có thể stream an toàn; cần spike kiểm chứng cả nguồn đọc và import, không mặc định dùng parallel restore khi input không seekable.

- Không dùng `--clean`, `--create`, drop/recreate DB có dữ liệu hoặc restore đè trong MVP. Kết nối tới đúng database được chỉ định, không chuyển sang tên DB trong archive.
- Tên database là giá trị literal, không diễn giải như libpq URI/conninfo. Connection fields được tách/escape bằng cơ chế tin cậy, không ghép shell; input có thể override host/user/dbname phải bị từ chối hoặc encode rõ nghĩa. Test dbname có dấu bằng, khoảng trắng và chuỗi giống connection URI.
- Đích không được là DB nguồn kể cả nguồn đang rỗng hoặc truy cập qua alias. Preflight so target cluster system identifier + database OID với source fingerprint trong snapshot. Không xác minh được thì từ chối; không fallback so hostname hoặc tên DB. Read identity bằng kết nối tin cậy tới cùng target được giữ cố định cho restore; không check endpoint này rồi import qua endpoint khác. Quyền đọc identity là prerequisite rõ, không tự cấp superuser.
- Đích phải là DB mới/rỗng: kiểm tra mọi schema không thuộc hệ thống, không chỉ bảng trong public; có user tables/views/sequences/functions/types hoặc extension ngoài baseline được hỗ trợ thì từ chối. Fresh DB baseline và cách kiểm tra được định nghĩa trong test; không coi query đếm public tables bằng zero là đủ. Operator phải giữ đích không có writer/DDL khác trong toàn restore; Bakabel không hứa cô lập được writer ngoài quyền kiểm soát.
- Policy MVP **bảo toàn owners/ACL của các object trong dump mà pg_restore xử lý**, không thêm remap mode hoặc toggle. Roles, memberships, tablespaces và extension binaries cần thiết do operator chuẩn bị ở cluster đích; không tự tạo role, cài extension, bỏ ownership/ACL hoặc backup globals. Không đáp ứng thì báo rõ unsupported/missing prerequisite hoặc restore failure, không âm thầm bỏ quyền.
- Owner/ACL **của chính database đích** là prerequisite riêng do operator thiết lập theo metadata snapshot trước khi import, vì Bakabel cấm `--create`. Không hứa pg_restore tự khôi phục quyền này. Preflight so owner name và normalized database ACL theo role names/privileges/grant options, xử lý PUBLIC và default ACL; không khớp hoặc không xác minh được thì từ chối trước khi ghi. Read back sau import; sai khác thì restore không được báo đạt policy preserve dù pg_restore exit 0. Không tự sửa quyền hoặc nới PUBLIC CONNECT để chạy cho xong. Các thuộc tính database khác như per-database settings/comment không được ngầm tuyên bố đã clone; operator chuẩn bị riêng khi ứng dụng cần.
- Restore toolchain phải tương thích dump/server; không bundle mọi phiên bản PostgreSQL client trong image chính. Helper client image/version tin cậy được resolve rõ khi restore; disk/image overhead phải được tính, không coi là miễn phí.
- Restore thất bại có thể để lại DB đích một phần: báo lỗi và giữ chẩn đoán, không chuyển traffic hoặc tuyên bố rollback toàn bộ. Không tự xóa đích thất bại nếu chưa được phép.
- Phân biệt `restored` (import hoàn tất) và application verification; query/data acceptance là nghiệm thu riêng. Chỉ chạy test restore với snapshot tin cậy; database dump có thể chứa lệnh thực thi.
- Kiểm tra cả Restic reader/helper và pg_restore kết thúc thành công; import exit 0 không đủ khi reader lỗi. B2 bắt buộc restore sang cluster mới với roles khác, không còn Docker container nguồn và không có state cũ. Operator chuẩn bị role/extension prerequisites và owner/ACL cấp database theo handoff rồi chứng minh cả object owners/ACL, database owner/ACL và data đúng; không phụ thuộc quyền/mapping vô tình còn trên fixture backup.

### File restore

Khôi phục đúng target snapshot vào thư mục rỗng/volume mới được chỉ định. Không tự restore vào mount ứng dụng đang dùng. Kiểm tra kết quả, path mapping và metadata/permissions theo khả năng runtime. Không tự deploy service hoặc đổi mount.

Preflight target không chỉ so path hoặc volume name: resolve canonical backing storage trên đúng daemon/node, phát hiện symlink/bind aliases, cùng filesystem object và quan hệ parent/child với nguồn/repository/state. Volume phải mới và không có consumer đang dùng; directory phải rỗng và có ownership phù hợp. Không chứng minh target khác nguồn hoặc backend che identity/alias thì từ chối. Không tái resolve qua đường tùy ý sau check; identity/empty checks và thao tác ghi phải tránh swap symlink/mount. B2 gate bao gồm source rỗng, tên volume khác nhưng cùng backing directory, bind/symlink alias và source/target nesting; không tuyên bố hỗ trợ mọi network volume driver.

Dữ liệu đích là dung lượng cần có; tiết kiệm staging không có nghĩa restore không cần ổ đĩa.

## 7. Scheduler, khóa, retention và cleanup

- Khóa atomic cho backup/restore/maintenance qua Bakabel cùng installation; được giữ bao phủ worker **và source export** lifetime, không chỉ PID scheduler. Không nhả khóa chỉ vì worker mất.
- Atomic worker identity/name và state tối thiểu phải xử lý hai launcher cùng lúc, scheduler restart, kill và stale state. Không coi Restic lock là toàn bộ workflow mutex.
- Khi chưa chứng minh worker cũ kết thúc, không tạo worker mới hoặc xóa tài nguyên của nó. Chỉ adopt/cleanup tài nguyên có identity/ownership đúng.
- Không retry vòng lặp vô hạn hoặc bù mọi lịch missed thành burst. Chốt quy tắc một lượt đến hạn, báo overdue và tiếp tục lịch chung.
- Retention optional, mặc định tắt; phải có restore test và operator approval vận hành trước khi bật forget/prune, không xây workflow approval trong sản phẩm. Không chạy destructive cleanup sau lượt backup lỗi. Lệnh Restic chạy trực tiếp ngoài Bakabel không nằm trong mutex Bakabel: operator phải tránh overlap; giữ native Restic locks và không dùng unlock tùy tiện.
- Không tự init repository chỉ vì truy cập repository thất bại; init là thao tác operator rõ ràng.
- Cache tạm dọn theo lượt để không tích lũy vô hạn; chấp nhận metadata re-download. Restic có thể vẫn dùng disk tạm, phải đo và kiểm tra failure khi hết dung lượng.
- Dọn đúng worker, temp credentials và temp files thuộc lượt đã kết thúc; không Docker system/image/build-cache prune, không động dữ liệu đích restore hoặc repository như rác.
- State nhỏ, stdout logs không chứa dump/secret; deployment examples có Docker log rotation.
- Failure notifications qua webhook tùy chọn; overdue/scheduler chết cần health/monitoring ngoài. Không thêm server để làm monitoring. Notification failure phải được phân biệt với backup result, không gửi secrets.

## 8. Resource/image contract

- Multi-stage Go build, baseline x86-64-compatible; release runtime image chỉ giữ Bakabel, Restic, CA certificates và timezone data cần thiết. Không compiler/source/Python/Docker CLI/debug toolchain.
- One image cho scheduler/worker. Công cụ phục hồi PostgreSQL dùng helper image khi cần, không nhồi mọi client vào base.
- Một target tại một thời điểm, buffers giới hạn, không tar/copy trung gian cho volume; PostgreSQL ưu tiên streaming theo gate ở trên.
- Worker limits configurable với defaults được đo; không thêm hàng loạt knobs vô căn cứ. CPU limit worker không giới hạn mọi side effect ở nguồn DB.
- Đo process/cgroup scheduler lúc idle, worker peak và tải nguồn; đo compressed image transfer, unpacked image disk, state/cache/temp peak, logs và residue sau success/failure/kill.
- Đo cả repository lớn hơn fixture nhỏ (index/cache/RAM Restic), helper image còn lưu trên host, DB đích CPU/I/O/WAL khi restore và lượt backup thứ hai trên file không đổi. Buffer bounded không đồng nghĩa toàn bộ Restic RAM bounded. Không tự prune helper images dùng chung để làm đẹp số đo.
- Không dùng benchmark scheduler stdlib-only làm cam kết RAM sản phẩm. Không đặt ngưỡng MB giả định trước khi đo.
- S3 không giữ mirror repository đầy đủ trên host. Local repository persistent là backup data, không bị cleanup như cache; cùng server không bảo vệ mất server.

## 9. Lộ trình/WBS và gates

Đây là WBS và các gate bắt buộc, không phải bảng xác nhận đã hoàn thành. Bằng chứng implementation phải gắn với đúng source/image revision; baseline PASS không tự chứng nhận candidate đã sửa.

| ID | Giai đoạn | Đầu ra/gate |
|---|---|---|
| B1 | Contract + spike streaming/cancellation/metadata | Helper exec -> Restic không tạo snapshot dump lỗi; SIGKILL/lock-wait/disconnect/restart không mất ownership export; chọn versioned tags/path và complete/partial/unknown có exact snapshot ID/readback |
| B2 | Compose/local one-shot + independent restore | plan/run/snapshots/restore; physical identity và empty-target gates; nguồn/state không còn; object owners/ACL + operator-prepared database owner/ACL prerequisites; files round trip; stream errors và partial/unknown bị chặn |
| B3 | Swarm + S3 | Service labels/task/node; một node manager; actual S3-compatible fixture backup/restore; không label/mount registry tập trung |
| B4 | Scheduler/lifecycle | Serve, cron/timezone, atomic overlap, restart/adoption/cancellation, cleanup/notification semantics |
| B5 | Package/resource/release readiness | Minimal pinned image, CI, auth-safe docs, full acceptance matrix, idle/peak/disk report |
| B6 | Tích hợp repo deployment hiện tại | Chỉ sau acceptance và yêu cầu riêng; independent backup preset/project; không tự deploy |
| Later | Kubernetes | Thêm platform implementation, không viết lại core; chưa dựng code hoặc CRD trong MVP |

Nếu B1 streaming correctness không đạt, dừng và xin quyết định trước khi thay kiến trúc. Không vá upstream, không tạo fork stack-back.

## 10. Acceptance matrix bắt buộc

- Compose và Swarm: thêm nguồn hợp lệ qua metadata không phải sửa danh sách target/mount trung tâm; project/stack backup update không redeploy apps.
- Hai kiểu nguồn x hai backend: PostgreSQL và files, local và S3-compatible; read back exact snapshot rồi restore dữ liệu fixture vào đích riêng.
- DB chạy đọc/ghi khi dump; source service không bị stop/restart/scale-down. Test restore schema, representative data/queries; không chỉ `restic check`.
- Dump fail sau partial output, dump chờ lock, Docker stream fail/disconnect, unknown exec status, upload fail, wrong credentials/password, missing repository, no targets, source task replaced, unsupported replica/node. Worker SIGKILL và scheduler restart phải xác nhận source export/session terminal trước khi release ownership hoặc chạy lượt mới.
- File unreadable/changed while reading, missing/wrong mount, source/repository alias hoặc nesting, path traversal, source secrets/socket, source permission preservation.
- Hai run đồng thời; backup vs restore/maintenance; scheduler killed/restarted khi worker còn chạy; worker killed; stale/corrupt state; timeout nguồn dump và bounded cleanup.
- Restic exit 3/unreadable file: receipt có snapshot ID và lỗi; crash trước/sau finalize; xóa state, dùng snapshots/restore từ môi trường sạch. Complete/partial/unknown và old/new snapshot ID phải đúng; không được phục hồi bản thiếu như bản đầy đủ.
- Restore missing/unsupported metadata, incompatible client/server, wrong target, alias host/DB/mount, source rỗng, user objects ngoài public, conninfo injection, nonempty target, no access, reader/import errors. Không sửa ứng dụng/volume nguồn hoặc tự xóa target sau partial failure.
- Fresh-cluster restore không còn source/state: role/ACL khác, missing role/extension prerequisites rồi cung cấp đúng; kiểm tra object owners/ACL và data thật. Fixture nguồn có database owner riêng và `REVOKE CONNECT FROM PUBLIC`: đích ban đầu khác database owner/ACL phải bị từ chối trước import; sau operator thiết lập đúng prerequisite từ repository thì restore đạt và read back database owner/ACL vẫn đúng. Thử cả ACL NULL/default và role OID khác nhau giữa cluster, không so raw OIDs.
- Lượt file backup thứ hai với worker khác vẫn chọn đúng parent, không đọc lại toàn bộ content do hostname/path thay đổi.
- Cron invalid không fallback; supported schedule/timezone được exercise; failure và overdue detection được chứng minh, không chỉ log success.
- Secret values không trong argv, prompts, logs, state, snapshot metadata hoặc committed artifacts. Worker nhận đúng credential files; thử cả Compose và Swarm secret-delivery mechanism được chọn.
- Disk full trong buffer/cache/output; không giữ full local DB dump trong streaming mode; residue sau success/failure/restart có ownership và được thu hồi an toàn.
- Giữ native Restic locks; nonzero/partial status không bị cleanup/alert che. Chỉ reporting success nếu criteria đủ.
- Build/test trên VPS hiện tại giới hạn tối đa hai CPU. Fixture services/credentials/repositories disposable; không chạm production, không gọi S3 thật ngoài scope đã duyệt.
- Trước release: independent correctness/security/simplicity review; actionable blockers giải quyết rồi re-review đúng revision.

## 11. Kubernetes sau MVP

- Labels cho selection, annotations cho cấu hình chi tiết trong Pod template; không dùng Docker key/value constraints như thể giống Kubernetes.
- Chỉ query Kubernetes API đầu lượt; CronJob gọi run để không thêm scheduler deployment thường trực; Job worker, Secret/RBAC đúng namespace.
- PostgreSQL trước. PVC phải xét access mode, node topology và CSI capabilities; không tự mount mọi PVC hoặc hứa snapshot app-consistent.
- Không dùng Docker socket/host storage paths làm Kubernetes API; giữ cùng adapter/pipeline Restic ở core.
- Metadata backup ổn định và self-contained để restore trên máy mới; Kubernetes-specific source access không làm đổi repository format thiếu version.

## 12. Review cần Astra trả lời

Review chỉ đọc bản plan này, không implement hoặc tự đổi yêu cầu. Ưu tiên:

1. Có phần nào thừa so với one-shot + scheduler nhẹ không?
2. Streaming và metadata có đáp ứng không tạo snapshot dump lỗi và khôi phục trên máy mới không?
3. Restore mới/rỗng, source identity, locks, credentials/mounts có lỗ hổng hoặc mâu thuẫn không?
4. Có chi phí CPU/RAM/đĩa bị bỏ sót hoặc tradeoff chưa nói rõ không?
5. WBS/gates đủ cụ thể để implement bằng TDD mà không over-engineer không?

Trả finding có severity, section, impact và thay đổi nhỏ nhất. Tách blocker khỏi cải tiến optional. Không coi plan là implementation đã kiểm chứng.

### Trace findings vòng 1 -> revision 2

| Finding | Contract/gate đã bổ sung |
|---|---|
| R1-H1 cancellation/export còn sống | §5.2 + §7 + B1: persist exec identity trước start, exact cancellation, terminal readback, blocked/quarantine qua restart; SIGKILL/lock-wait/disconnect probes |
| R1-H2 restore identity/target | §5.1 + §6 + B2: physical source fingerprint, alias/nesting, literal dbname, cấm create/clean và check mọi non-system schema; unverifiable là từ chối |
| R1-M3 partial snapshot sau mất state | §5.4 + §6 + §10: repository status unknown -> complete/partial, final snapshot ID readback, receipt có ID và lỗi, chỉ restore complete |
| R1-M4 independent restore/owners | §5.4 + §6 + B1/B2: versioned tags/path, cố định preserve owners/ACL với operator prerequisites; restore cluster mới không còn source/state |
| R1-M5 Restic parent/footprint | §5.3 + §8 + §10: stable hostname/path/grouping, kiểm thử lượt file không đổi tiếp theo; thêm index/cache/helper-image/target-WAL measurements |

Policy preserve owners/ACL là lựa chọn thiết kế bảo thủ cho revision này, không phải lời tuyên bố user đã chọn giữa hai chế độ. Nếu user muốn portability bằng remap thì quyết định riêng; không tự thêm hai mode trong MVP. Các finding chỉ được coi đã đóng ở mức plan sau re-review, không thay bằng bằng chứng implementation.

### Trace vòng 2 -> revision 3

- R2-M1 (§5.4, §6, B2/§10): giới hạn preserve tự động vào object trong dump; database-level owner/ACL là operator prerequisite có metadata normalized role-name/default/PUBLIC cùng snapshot, preflight/readback bắt buộc. Thêm fixture owner riêng + REVOKE CONNECT FROM PUBLIC; không dùng --create, không thêm remap/auto-grant hoặc backup globals.

## Nguồn kỹ thuật đã đối chiếu

Revision 4 / R1-C01: người dùng đã chọn giữ Compose stateless và chỉ cam kết availability cho service còn metadata container quan sát được; không cam kết phát hiện service đã bị xoá hết container. Swarm vẫn giữ zero-running-task failure cho service object còn tồn tại. Đây là quyết định contract tường minh, không phải suy ra approval từ limitation trong docs.

Các nguồn dưới đây hỗ trợ nguyên tắc, không chứng minh Bakabel đã implement:

- Restic command streaming/exit semantics: https://restic.readthedocs.io/en/stable/040_backup.html#reading-data-from-a-command
- Docker deploy labels là service metadata: https://docs.docker.com/reference/compose-file/deploy/#labels
- Kubernetes labels/annotations: https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/ và https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/
- Kubernetes CronJob: https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/
- PostgreSQL pg_dump/pg_restore: https://www.postgresql.org/docs/current/app-pgdump.html và https://www.postgresql.org/docs/current/app-pgrestore.html
