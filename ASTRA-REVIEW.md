# Bakabel — Astra Plan Review

- Verdict: **READY_WITH_CHANGES**.
- Reviewer model verified in persisted session: `gpt-6-astra`.
- Provider requested: `custom-codex_responses`; persisted billing endpoint matches `https://cli-proxy-api-llm-internal.genkisol.com/v1`.
- Requested reasoning: `high`; native persisted metadata does not independently expose reasoning level.
- Session: `local-ca259fab3357b9dc5f9899972afa9f5ead3b9a320c64b3014a22451a930638f2`.
- Reviewed artifact: `PLAN.md`.
- Reviewed SHA-256: `17a42f154019a3daeb9a5f651206688087f2387a57c347dc2be5298be75ac312`.
- CLI exit: `0`. Only web_search/web_extract were used by reviewer; no filesystem tools.
- Plan was unchanged throughout review. Findings below have **not** been applied.
- Verification artifacts: `/home/tamnt/.hermes/cache/scratch/bakabel-astra-review-npbdbb5l`.
- First launch was rejected locally for unsupported gateway `--run-budget`; removed only that flag and retried, without config changes or provider/model fallback.

## Reviewer output

READY_WITH_CHANGES

Kiến trúc khả thi, đúng phạm vi MVP. Chưa thấy lý do đổi Go/Restic hoặc thêm framework. Cần siết các contract dưới đây trước khi triển khai phần tương ứng; chưa thể coi streaming đã được chứng minh. Review dựa trên nội dung cung cấp, không xác minh hash của file trên đĩa.

Findings bắt buộc

1. High — §5.2, §7, B1/B4: cancellation phải bao phủ exec còn sống, không chỉ worker.

   Docker exec không bảo đảm dừng khi client disconnect hoặc helper bị kill. pg_dump đang chờ lock, chưa ghi stdout, cũng không nhất thiết gặp broken pipe. Worker chết nhưng exec sống khiến khóa được nhả sai và lượt sau chồng lên export cũ.

   Thay đổi nhỏ nhất: đưa spike cancellation vào B1, không chờ B4; chốt cơ chế dừng đúng export, kiểm chứng danh tính trước khi signal và xác nhận exec kết thúc. Khóa chỉ được nhả khi cả worker lẫn export đã kết thúc. Probe phải có worker SIGKILL, dump chờ lock, mất kết nối Docker và restart scheduler. Không dùng kill toàn container hoặc pkill theo tên. Nếu không chứng minh được trong phạm vi nguồn hỗ trợ: BLOCKED tại B1, đúng chủ trương không tự thêm staging.

2. High — §5.1, §6: logical source ID chưa đủ bảo vệ restore target.

   Project/service/database xác định nguồn logic, không chứng minh hai endpoint khác nhau trỏ tới hai DB khác nhau. So hostname hoặc tên DB có thể bỏ lọt alias. Tương tự, hai đường dẫn/volume có thể trỏ cùng storage.

   pg_restore --create còn có thể chuyển sang tên DB trong archive thay vì DB đích; tham số dbname dạng conninfo có thể override connection options.

   Thay đổi nhỏ nhất: chốt contract identity vật lý và cách xác minh đích trước ghi; không xác minh được thì từ chối. Cấm --create, không diễn giải tên DB như conninfo ngoài ý muốn. Test alias endpoint, alias mount, source đang rỗng và DB có object ngoài public schema; “rỗng” không chỉ là không có bảng trong public.

3. Medium — §5.3–5.4, §6, §10: partial snapshot có thể xuất hiện như backup hoàn chỉnh trên máy mới.

   Restic backup exit 3 vẫn tạo snapshot thiếu file. Plan đúng khi không báo run thành công, nhưng kết quả “snapshot ID hoặc lỗi” làm mất khả năng biểu diễn cả hai. Máy mới không có state có thể thấy snapshot mang metadata bình thường rồi restore một tập dữ liệu thiếu.

   Thay đổi nhỏ nhất: cho phép kết quả gồm cả snapshot ID và lỗi; chốt cách repository biểu đạt trạng thái complete/partial/unknown, không gắn “complete” trước kết quả. Restore không được trình bày partial/unknown như bản đầy đủ. Test unreadable file và crash ở ranh giới commit/report, sau đó xóa state, dùng snapshots/restore từ môi trường sạch. Không cần catalog riêng.

4. Medium — §4, §5.4, §6, B1/B2: nghiệm thu restore cần độc lập thực sự với nguồn.

   Metadata bằng tags/path là hướng khả thi cho streaming; plan đã nhận đúng giới hạn manifest. Tuy nhiên round trip trên fixture cũ có thể vô tình dùng role, extension, cấu hình hoặc mapping còn tồn tại. Không backup globals là hợp lệ, nhưng pg_restore mặc định vẫn tham chiếu owners/ACL; import sang cluster mới có thể lỗi dù fixture đơn giản xanh.

   Thay đổi nhỏ nhất: B1 chốt metadata versioned và path chính xác trong snapshot; B2 thêm restore khi container nguồn và state không còn truy cập được. Chốt một policy owners/ACL: bảo toàn với prerequisites do operator cung cấp, hoặc remap có mô tả rõ. Test role khác nhau và extension thuộc phạm vi hỗ trợ; không cần thêm backup globals. Kiểm tra cả exit của Restic đọc dump và pg_restore, không chỉ phía import.

5. Medium — §5, §8: hostname worker tạm có thể làm backup file đọc lại toàn bộ.

   Restic mặc định chọn parent theo hostname và paths. Nếu mỗi worker dùng hostname mới, hoặc mount path chứa run ID, backup tuần tự vẫn mất lợi ích phát hiện file không đổi, tăng CPU/I/O và thời gian chạy.

   Thay đổi nhỏ nhất: chốt hostname/grouping và đường đọc ổn định theo source identity; không đưa run ID vào nhóm parent. Benchmark hai lượt liên tiếp trên dữ liệu không đổi, không chỉ lượt đầu. Không cần thêm knob cho người dùng.

Các điểm cần giữ làm gate, không coi là lỗi chỉ vì chưa implement

• Credentials Swarm (§4/B3): nhận định “worker không kế thừa secret mounts” là đúng. Cần chọn đúng một cơ chế rồi test secret thật, không dùng fixture Env thay thế. Nếu dùng service tạm, đặt rõ restart policy để task không tự chạy lại backup. Nếu chuyển secret qua API, không dựa vào bind path chỉ tồn tại trong scheduler; kiểm tra residue khi kill/restart.

• Locks (§7): atomic ownership, không tự dọn worker chưa xác minh và giữ native Restic locks đều đúng. Cần áp dụng thêm phạm vi export ở finding 1. Maintenance chạy Restic trực tiếp nằm ngoài mutex Bakabel: docs phải yêu cầu operator tránh overlap, không hứa khóa được lệnh ngoài.

• Footprint (§8): phạm vi đo tốt. Bổ sung vào cùng báo cáo chi phí index/cache khi repository lớn, helper image tồn dư và CPU/I/O/WAL phía DB đích khi restore. Buffer giới hạn không đồng nghĩa tổng RAM Restic giới hạn. Không cần đặt ngưỡng MB trước đo.

Phần thừa có thể cắt — optional

• §11 rút còn “Kubernetes sau MVP”; các quyết định Job/CSI/RBAC chưa phục vụ nghiệm thu hiện tại.
• Webhook hoãn nếu chưa có nhu cầu; giữ kết quả, exit status và hướng dẫn monitoring ngoài.
• Retention giữ mặc định tắt và hướng dẫn Restic; chưa cần xây workflow approval trong sản phẩm.

Phần tốt giữ nguyên

• Một lịch, một repo, tuần tự; discovery đến lịch, worker tạm.
• Type là opt-in; không khôi phục enable/consistency.
• Không stop app, không staging fallback âm thầm, không tự init hoặc prune rộng.
• Restore đích mới/rỗng, exact snapshot, không tự chuyển traffic.
• Phân biệt backup dữ liệu với application verification; acceptance có failure probes thực.

Cần user quyết định

• Owners/ACL: bảo toàn với prerequisites hay remap về role đích?
• Cơ chế cấp credentials Swarm chỉ cần hỏi user nếu đòi thêm quyền hoặc vị trí lưu secret; không cần hỏi để chọn chi tiết nội bộ.
• Nếu B1 không đạt cancellation/streaming: dừng xin quyết định, không tự đổi kiến trúc.

REVIEWED_PLAN_SHA256=17a42f154019a3daeb9a5f651206688087f2387a57c347dc2be5298be75ac312
