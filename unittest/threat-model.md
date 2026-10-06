# Threat Model cho `json_search()`

## 1. Actor/Role và mục đích

- **Admin:** Được phép truy xuất toàn bộ dữ liệu cần thiết cho quản trị, cấu hình mạng và khắc phục sự cố.
- **Operator:** Được phép truy xuất trạng thái hoạt động và các metrics phục vụ giám sát vận hành; **không được phép truy cập thông tin xác thực**.
- **Viewer:** Chỉ được phép xem thông tin tổng quan và trạng thái up/down cơ bản; **không được phép truy cập topology chi tiết hoặc dữ liệu nhạy cảm**.

## 2. Assets nhạy cảm

Các dữ liệu nhạy cảm có thể xuất hiện trong JSON trả về gồm:

- SNMP community strings.
- API keys, passwords, tokens và các thông tin xác thực khác.
- Địa chỉ IP nội bộ.
- MAC addresses.
- Thông tin topology và routing nội bộ.

Các dữ liệu này nếu bị tiết lộ có thể cho phép người dùng trái phép truy cập hoặc thu thập thông tin về hệ thống mạng.

## 3. Trust Boundary

Trust boundary nằm giữa:

> **User/Client + Role Context → `json_search()` → Internal JSON/API Data**

Nếu `json_search()` thực hiện tìm kiếm và trả kết quả mà **không kiểm tra quyền của `role`**, dữ liệu từ vùng tin cậy cao (internal data) có thể được trả trực tiếp cho user có mức quyền thấp hơn.

Do đó, việc tìm thấy một key trong JSON **không đồng nghĩa với việc user được phép nhận giá trị của key đó**.

## 4. STRIDE Threat Model

### Threat 1 — Information Disclosure

- **Actor:** `viewer` hoặc `operator`.
- **Attack:** User thực hiện tìm kiếm các key như `snmp`, `password`, `token` hoặc `api_key`.
- **Impact:** `json_search()` trả về giá trị credential hoặc thông tin mạng nội bộ mặc dù role không có quyền truy cập.

**Ví dụ:**

```text
viewer → json_search("snmp")
       → "public-community-secret"
```
Điều này gây **Information Disclosure** vì thông tin xác thực bị tiết lộ cho role không đủ quyền.

### Threat 2 — Elevation of Privilege

- **Actor:** Attacker sử dụng tài khoản `operator` hoặc `viewer`.
- **Attack:** Lợi dụng `json_search()` để truy xuất credential hoặc thông tin nội bộ vốn chỉ dành cho `admin`. 
- **Impact:** Attacker có thể sử dụng credential thu được để truy cập các thành phần khác với quyền cao hơn. 

Điều này tạo ra nguy cơ **Elevation of Privilege**.