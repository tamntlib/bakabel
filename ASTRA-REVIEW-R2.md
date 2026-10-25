# Bakabel — Astra Plan Review, Round 2

- Verdict: **READY_WITH_CHANGES**.
- Verified model: `gpt-6-astra`; requested provider: `custom-codex_responses`.
- Persisted billing endpoint: `https://cli-proxy-api-llm-internal.genkisol.com/v1`; exact match with launch expectation.
- Requested reasoning: `high`; native persisted metadata does not independently expose reasoning level.
- Session: `local-a917f690265084c2e07f31c4c2c425ebdcda640578f7b9893f575fef0da221e5`; source: `tool`; CLI exit: `0`.
- Artifact: `PLAN.md`, revision 2; SHA-256: `dcaf2e3e0ddb1a2a16cf294920e31385e09895f05e97fbb8a9f5205de40d196e`.
- Plan was unchanged during review. Round-1 contracts were added before launch; new R2-M1 has **not** been applied.
- Read-only review; only web_search/web_extract were available/used by reviewer, no filesystem tools.
- Evidence directory: `/home/tamnt/.hermes/cache/scratch/bakabel-astra-r2-kt050m49`.
- Previous review remains in `ASTRA-REVIEW.md` for its original revision/hash.

## Reviewer output

READY_WITH_CHANGES

Revision 2 đã xử lý phần lớn findings vòng 1 ở mức contract và acceptance gates. Còn một điểm Medium: lời hứa bảo toàn owners/ACL chưa phân biệt quyền của chính database với quyền của các object bên trong khi cấm pg_restore --create.

Đây là review nội dung được cung cấp, không xác minh file hoặc SHA256 trên đĩa, không truy cập hệ thống live. CLOSED_AT_PLAN_LEVEL không có nghĩa implementation hoặc spike đã đạt.

Bảng closure

Finding   Section                   Trạng thái
R1-H1     §5.2, §7, B1, §10          CLOSED_AT_PLAN_LEVEL
R1-H2     §5.1, §6, B2, §10          CLOSED_AT_PLAN_LEVEL
R1-M3     §5.4, §6, B1/B2, §10       CLOSED_AT_PLAN_LEVEL
R1-M4     §5.4, §6, B1/B2, §10       PARTIAL
R1-M5     §5.3, §8, §10              CLOSED_AT_PLAN_LEVEL

Căn cứ closure

1. R1-H1 — Đã chuyển cancellation vào B1, bao phủ export thay vì chỉ worker. Persist identity trước start, kiểm chứng trước signal, xác nhận terminal, quarantine qua restart và không release khi mất khả năng inspect là contract phù hợp. Các probe SIGKILL/lock-wait/disconnect/restart đúng trọng tâm. Chưa chọn cơ chế hủy cụ thể không phải finding mới: B1 đã được giao chứng minh và phải BLOCKED nếu không đạt.

2. R1-H2 — Đã tách logical identity khỏi physical fingerprint; xử lý alias, nguồn rỗng, nesting, target swap và từ chối trường hợp không chứng minh được. Cấm --create/--clean, kiểm tra ngoài public và chống conninfo injection đều đáp ứng finding cũ. Tính khả thi của phạm vi storage được hỗ trợ và cách giữ đúng endpoint phải được chứng minh ở B2, không cần giải quyết mọi volume driver ngay trong plan.

3. R1-M3 — Repository chứa trạng thái unknown/partial/complete; receipt chứa đồng thời ID và lỗi; finalize có mapping ID/readback; restore từ môi trường sạch từ chối partial/unknown. Đã khép lỗ hổng mất state. Crash trong tag mutation có thể cần xử lý nhiều snapshot cùng run/target; yêu cầu không chọn newest và không chấp nhận metadata mâu thuẫn đã đặt đúng giới hạn an toàn.

4. R1-M4 — Versioned metadata, exact dump path, independent restore, prerequisites và kiểm tra cả reader/import đều đã bổ sung. Còn thiếu ranh giới chính xác của preserve owners/ACL, nêu trong R2-M1 dưới đây. Việc user chưa xác nhận policy là quyết định còn chờ, không phải bằng chứng thiết kế không khả thi.

5. R1-M5 — Stable hostname, đường đọc, grouping host,paths và phép thử lượt hai đã đủ ở mức plan. Đã bổ sung chi phí repository lớn, helper image và DB đích; không nhầm bounded buffer với bounded RAM toàn Restic.

Finding mới bắt buộc

R2-M1 — Medium — §6 PostgreSQL restore, §5.4, B2/§10
Phạm vi preserve owners/ACL chưa khớp với restore không dùng --create.

Theo tài liệu pg_restore, --create mới phục hồi access privileges của chính database; chế độ này cũng xử lý các thuộc tính database liên quan. Khi import vào database có sẵn mà không dùng --create, không thể suy rằng owner/ACL cấp database sẽ được phục hồi giống owner/ACL của bảng, schema và các object trong archive.

Impact:
Một DB nguồn đã REVOKE CONNECT FROM PUBLIC có thể được import thành công vào DB mới vẫn cho PUBLIC CONNECT. Dữ liệu và ACL bảng đúng nhưng kết quả vẫn không đáp ứng lời hứa “bảo toàn owners/ACL”. Chuẩn bị đủ roles/memberships chưa giải quyết khác biệt này.

Sửa nhỏ nhất:
  - Giữ nguyên lệnh cấm --create; không thêm remap mode.
  - Ghi rõ Bakabel phục hồi owners/ACL của các object được pg_restore xử lý; owner/ACL của chính database là prerequisite do operator thiết lập trên đích.
  - Handoff từ repository phải đủ thông tin cho prerequisite này, không cần globals/password hoặc catalog riêng.
  - B2 thêm fixture có database owner riêng và REVOKE CONNECT FROM PUBLIC; kiểm tra cả quyền cấp database, không chỉ table/schema ACL. Không báo đạt tiêu chí preserve nếu prerequisite chưa được đáp ứng.

Đây là việc làm rõ một lời hứa có thể sai dù pg_restore exit 0, không phải yêu cầu viết implementation trong giai đoạn authoring.

Tổng actionable mới: 0 High, 1 Medium.

Gates cần giữ, không nâng thành findings

- B1 vẫn phải chứng minh streaming và cancellation trên image nguồn hỗ trợ. Không được đóng gate chỉ vì Docker exec đã được ghi state hoặc tài liệu Restic mô tả command failure.
- B2 phải chứng minh restore độc lập, physical identity và chống target swap; fail-closed là chấp nhận được cho backend không đủ bằng chứng.
- Secret delivery Swarm phải được thử bằng secret thật tại B3. Chưa chọn chi tiết nội bộ ở revision này không buộc thêm daemon/framework.
- Không tự chuyển sang staging nếu backup hoặc restore streaming không đạt correctness.

Optional, không ảnh hưởng verdict

Có thể rút §11 xuống phạm vi “Kubernetes sau MVP” và hoãn webhook. Không cần thêm thành phần runtime; độ phức tạp tăng hiện tại chủ yếu nằm ở failure contracts cần thiết.

Câu hỏi user trước B2

Có chấp thuận policy MVP bảo toàn owners/ACL, với roles/memberships/tablespaces/extension binaries và owner/ACL cấp database do operator chuẩn bị theo handoff hay không? Đây là lựa chọn thiết kế đề xuất, chưa phải quyết định user đã xác nhận. Không mặc nhiên thêm chế độ remap.

Nguồn đối chiếu

https://www.postgresql.org/docs/current/app-pgrestore.html
https://restic.readthedocs.io/en/stable/040_backup.html

REVIEWED_PLAN_SHA256=dcaf2e3e0ddb1a2a16cf294920e31385e09895f05e97fbb8a9f5205de40d196e
