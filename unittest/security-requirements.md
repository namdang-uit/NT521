# Security Requirements cho `json_search()`

## SR-1 — Role-based Access Control (RBAC)

`json_search()` **MUST kiểm tra role của caller trước khi trả về dữ liệu**.

Mỗi role chỉ được phép truy cập các nhóm dữ liệu tương ứng:

| Role | Basic status | Metrics | Topology | Credentials |
|---|---:|---:|---:|---:|
| `viewer` | ✅ | ❌/giới hạn | ❌ | ❌ |
| `operator` | ✅ | ✅ | ❌/giới hạn | ❌ |
| `admin` | ✅ | ✅ | ✅ | ✅ |

Quyền truy cập phải được xác định dựa trên **role**, không dựa trên việc user có biết tên key hay không.

## SR-2 — Sensitive Data Redaction

Nếu kết quả tìm kiếm chứa sensitive fields mà role hiện tại không được phép truy cập, `json_search()` **MUST không trả về giá trị thật**.

Có thể:

- Loại bỏ field khỏi kết quả; hoặc
- Thay giá trị bằng `[REDACTED]`.

Ví dụ đối với `operator` hoặc `viewer`:

    {
        "device": "router01",
        "status": "up",
        "snmp_community": "[REDACTED]"
    }

## SR-3 — Explicit Denial

Nếu user trực tiếp tìm kiếm một sensitive field mà role không có quyền truy cập, hàm phải từ chối truy cập.

Ví dụ:

    viewer → search("password")

Kết quả phải là `PermissionDenied` hoặc một kết quả rỗng an toàn.

**Không được trả về giá trị hoặc cấu trúc dữ liệu nhạy cảm.**

## SR-4 — Input Validation

`role` phải được validate **trước khi thực hiện JSON search hoặc trả về dữ liệu**.

Các role hợp lệ:

    admin
    operator
    viewer

Nếu role không hợp lệ:

    json_search(..., role="unknown")

phải bị từ chối thay vì mặc định cấp quyền hoặc bỏ qua kiểm tra.

## SR-5 — Least Privilege

`json_search()` phải áp dụng nguyên tắc **Least Privilege**:

> User chỉ được nhận đúng loại dữ liệu cần thiết cho chức năng của role đó.

Đặc biệt, **không được coi việc user có quyền gọi `json_search()` là đồng nghĩa với quyền đọc toàn bộ JSON**.

## SR-6 — Không bypass authorization qua search key

Authorization phải được thực hiện **trước khi giá trị nhạy cảm được đưa vào response**.

Luồng xử lý an toàn:

    Request
       ↓
    Validate role
       ↓
    Search JSON
       ↓
    Check permission của field
       ↓
    Redact / Deny / Return

Không được thực hiện theo luồng:

    Request
       ↓
    Search JSON
       ↓
    Return sensitive value
       ↓
    Check role  ❌

## 5. Tổng kết Threat → Security Requirement

| Threat | Security Requirement liên quan |
|---|---|
| Viewer đọc được SNMP/password/token | SR-1, SR-2, SR-3 |
| Operator đọc được credential của Admin | SR-1, SR-5 |
| Role không hợp lệ bypass authorization | SR-4 |
| Search trực tiếp sensitive key để bypass quyền | SR-3, SR-6 |
| User có quyền gọi function nhưng đọc toàn bộ JSON | SR-1, SR-5 |

Các Security Requirements trên sẽ được sử dụng làm cơ sở để xây dựng **Security Tests** cho `json_search()` ở bước tiếp theo.