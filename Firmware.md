Tìm chức năng update firmware.(`updateII.dat`, `UpdateT48.dat`, `updateT56.dat`).

**Hàm liên quan:** `sub_402810` (dispatcher chính, xử lý cả 3 loại), `sub_4030D0` (thực thi update cho II), `sub_403600` (T48), `sub_403A40` (T56), CRC dùng chung `sub_4EE6D0` với bảng `dword_6C3300` — đã dump và xác nhận đây là **CRC32 chuẩn IEEE 802.3** (poly `0xEDB88320`, init `0xFFFFFFFF`, complement cuối).

**updateII.dat (TL866-II Plus) — định dạng phức tạp nhất trong 3 file:**

Magic = `0xF8CC4284`. Cấu trúc file (đã verify khớp 100% với file thật, 936 block, CRC toàn file khớp chính xác `0x4FA3C931`):

```
Header (1036 bytes):
  +0x000 magic (4B)          = 0xF8CC4284
  +0x004 crc32 toàn file (4B, stored)
  +0x008 bảng khoá XOR (1024 bytes)
  +0x408 số block (4B) = 936 (ví dụ file bạn có)

936 × Block thường (272 bytes):
  +0x00 crc32 riêng block (4B)
  +0x04 seed (4B, plaintext) -> chọn vị trí bắt đầu trong bảng khoá
  +0x08 địa chỉ flash (4B, byte thấp bị "obfuscate")
  +0x0C flags (4B)
  +0x10 payload 256 bytes

1 × Block cuối (2064 bytes, cùng layout, payload 2048 bytes)
```

Cơ chế "unpack": byte thấp nhất của trường địa chỉ bị XOR với chuỗi 264 (hoặc 2056 với block cuối) byte liên tiếp lấy từ bảng khoá 1024-byte trong header, bắt đầu tại vị trí `seed`. Đây **không phải mã hoá payload** — chỉ obfuscate 1 byte của địa chỉ, có vẻ là cơ chế chống giả mạo/replay file đơn giản. Em đã patch byte này bằng Python và crc32 mọi 936 block + block cuối đều khớp 100%.

**Điểm quan trọng:** payload thực tế (phần dữ liệu 256/2048 byte mỗi block) **không hề bị Xgpro.exe giải mã** — được gửi nguyên văn qua USB (`sub_4DC070`, lệnh `59`) tới chính con vi điều khiển bên trong TL866-II Plus. Em đo entropy của payload sau khi patch: ~7.9 bit/byte (gần random tuyệt đối 8.0), không có chuỗi ASCII/pattern rõ ràng nào — tức là firmware thật cho MCU trong máy TL866-II Plus đã được nhà sản xuất mã hoá/nén sẵn từ trước khi đóng gói vào file `.dat`. Việc giải mã lớp này (nếu có) chỉ xảy ra trong bootloader nội bộ của thiết bị, không nằm trong Xgpro.exe — nên không thể "unpack" tiếp bằng cách phân tích riêng file PC này.

**updateT48.dat / updateT56.dat — đơn giản hơn nhiều:**

Không có CRC, không có XOR-obfuscate gì cả. Chỉ có header 16 byte:
```
+0x00 magic (4B)   T56 = 0x56000149, T48 = 0xF0480127
+0x04..0x0B  reserved
+0x0C block_count (4B)
```
rồi đọc thẳng từng block cố định (T56: 2068 byte/block; T48: 276 byte/block) và bắn nguyên văn qua USB — không XOR, không CRC riêng từng block. T48 còn gửi thêm 1 lệnh "erase" cố định trước khi truyền.

Tóm lại: cả 3 file đều là **container thô chứa firmware MCU của thiết bị**, Xgpro.exe chỉ đóng vai trò kiểm tra tính toàn vẹn (CRC32/magic) và truyền dữ liệu qua USB — bản thân nội dung firmware bên trong (đặc biệt với II) đã được mã hoá/nén từ khâu sản xuất, ngoài tầm với của việc phân tích riêng Xgpro.exe.

**`extract_fw_update.py`** — pure Python 3 stdlib, không cần IDA. Tự nhận diện cả 3 loại file qua magic number.

```
python extract_fw_update.py updateII.dat out_II
python extract_fw_update.py updateT48.dat out_T48
python extract_fw_update.py updateT56.dat out_T56
```

Mỗi lần chạy ra 2 file: `<prefix>.header.json` (metadata + kết quả verify CRC) và `<prefix>.firmware.bin` (blob firmware thô, đã ghép đúng thứ tự, byte địa chỉ đã de-obfuscate với updateII.dat).

Đã verify bằng cách chạy lại chính xác thuật toán trong script trực tiếp trên 3 file thật:
- `updateII.dat`: magic khớp, kích thước file khớp công thức (`1036 + 936×272 + 2064 = 257692`), toàn bộ 936 block CRC + block cuối CRC + CRC toàn file đều khớp 100%.
- `updateT48.dat` / `updateT56.dat`: magic khớp, kích thước khớp block_count trong header (942 và 168 block tương ứng).
