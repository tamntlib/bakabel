# Bakabel — Astra Final Plan Review (Round 3)

- Final verdict: **READY — plan-level approval only**.
- Actionable mandatory findings remaining: **0 High, 0 Medium**.
- Verified reviewer model: `gpt-6-astra`; requested provider: `custom-codex_responses`.
- Persisted billing endpoint: `https://cli-proxy-api-llm-internal.genkisol.com/v1`; exact match with launch expectation.
- Requested reasoning: `high`; native persisted metadata does not independently expose reasoning level.
- Session: `local-09a187301cc8b25b78e4abefe161819b8230766ae1a475a8d2bcd6e475d820d2`; source: `tool`; CLI exit: `0`.
- Approved artifact: `PLAN.md`, revision 3; SHA-256: `1dacaf5eb5b9eb2330e8ddd007c5e76d4162a0445980f7edce6551c0c2673139`.
- Plan was unchanged during review and after verdict. Its submission-status line is retained to preserve the reviewed hash; this report records the final review status.
- R2-M1 and R1-M4 are closed at plan level; earlier finding closures remain valid per reviewer.
- Review was read-only; only web_search/web_extract tools were used. No code, Git repository, remote, image or deployment was created by this review loop.
- Optional grantor/grantee schema detail below is retained as a non-blocking implementation note; not patched into the approved plan after review.
- Evidence directory: `/home/tamnt/.hermes/cache/scratch/bakabel-astra-r3-lap4af0e`.
- Prior reports: `ASTRA-REVIEW.md` and `ASTRA-REVIEW-R2.md`, each bound to its own earlier plan hash.

## Reviewer output

READY

Chấp thuận revision 3 ở mức plan. Tổng actionable bắt buộc còn lại: 0 High, 0 Medium.

Review dựa trên toàn văn được cung cấp và tài liệu kỹ thuật đối chiếu; không đọc filesystem, không xác minh SHA256 trên đĩa, không truy cập hệ thống live hoặc sửa file. READY không có nghĩa spike đã đạt, release-ready, hay được phép implement/deploy.

Closure

1. R2-M1 — CLOSED_AT_PLAN_LEVEL
   Sections: §5.4, §6, B2, §10.

   Revision 3 đã sửa đúng ranh giới:
   - pg_restore chịu trách nhiệm ownership/ACL của object trong dump thuộc phạm vi nó xử lý.
   - Owner/ACL của chính database là prerequisite operator chuẩn bị; không dựa vào pg_restore khi cấm --create.
   - Repository chứa thông tin phục vụ prerequisite, dùng role names thay vì OIDs, xử lý PUBLIC, privileges, grant options và ACL NULL/default.
   - Preflight phải từ chối trước import khi không khớp hoặc không xác minh được; readback sau import ngăn báo preserve thành công chỉ dựa vào exit 0.
   - Fixture owner khác, REVOKE CONNECT FROM PUBLIC, default ACL và OIDs khác cluster đã có trong acceptance.

   Cách sửa này phù hợp tài liệu PostgreSQL: --create mới phục hồi ACL cấp database; ACL NULL biểu thị quyền mặc định, không phải không có quyền. Không phát sinh auto-grant, remap hoặc backup globals.

2. R1-M4 — CLOSED_AT_PLAN_LEVEL
   Sections: §5.4, §6, B1/B2, §10.

   Phần partial của vòng 2 được khép lại bởi R2-M1. Contract hiện đủ cho restore độc lập: metadata versioned gắn với snapshot, exact dump path, toolchain tương thích, prerequisites rõ, kiểm tra reader lẫn importer, và fixture cluster mới không còn source/state cũ.

   “Roles khác” trong fixture được hiểu là trạng thái đích ban đầu khác; operator sau đó chuẩn bị đúng roles/prerequisites theo policy preserve. Không phải yêu cầu tự đổi tên role hoặc thêm mapping.

Các findings vòng 1 khác giữ nguyên trạng thái đóng ở mức plan; không thấy revision 3 làm mất các bảo đảm đã bổ sung.

Đánh giá gates còn phải thực hiện

- B1: Đủ cụ thể để kiểm chứng streaming, command failure, cancellation và recovery. Persist exec ID không được coi là bằng chứng export đã chết. SIGKILL lúc chờ lock, disconnect, restart, terminal verification và quarantine đã bao phủ failure mode quan trọng. Không đạt thì BLOCKED, không tự staging fallback.
- B1 metadata: Encoding/size limits, status unknown/partial/complete, thay đổi snapshot ID khi finalize và readback đúng run/target đều có gate. Không phụ thuộc state local để nhận diện snapshot phục hồi được.
- B2: Bao phủ restore độc lập, identity nguồn/đích, alias/nesting, target swap, baseline database rỗng, lỗi stream và owner/ACL cấp database. Từ chối backend không chứng minh được identity là giới hạn hỗ trợ hợp lệ, không phải lối bỏ qua kiểm thử.
- B3–B5: Có thử secret delivery thực tế trên Swarm, ma trận nguồn/backend, concurrency/restart và đo resource toàn đường chạy. Không đánh đồng bounded buffers với bounded RAM của Restic hoặc worker limits với giới hạn tải DB nguồn.

Đây là các acceptance gates trước triển khai/release tương ứng, không phải yêu cầu phải có code hoặc spike đã chạy để chấp thuận tài liệu.

Actionable bắt buộc

Không có. Không phát hiện mâu thuẫn mới đủ căn cứ để giữ READY_WITH_CHANGES.

Optional

Khi chốt schema metadata ở B1, nên ghi rõ normalized ACL giữ cả grantor và grantee theo role name, không chỉ tập quyền hiệu dụng. Tài liệu PostgreSQL biểu diễn ACL theo từng cặp grantor/grantee; điều này giúp cụ thể hóa contract “normalized database ACL” đã có, không cần thêm mode hoặc thành phần.

Quyết định user

Không cần quyết định mới để tiếp tục authoring/review. Approval policy preserve vẫn cần trước triển khai, tách biệt với verdict tính nhất quán này. Quyền lặp sửa plan/review hiện tại không cấp quyền implement, chạy spike, tạo repository hoặc deploy.

Nguồn đối chiếu

https://www.postgresql.org/docs/current/app-pgrestore.html
https://www.postgresql.org/docs/current/ddl-priv.html
https://www.postgresql.org/docs/current/catalog-pg-database.html
https://restic.readthedocs.io/en/stable/040_backup.html

REVIEWED_PLAN_SHA256=1dacaf5eb5b9eb2330e8ddd007c5e76d4162a0445980f7edce6551c0c2673139
