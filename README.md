<img width="1191" height="743" alt="image" src="https://github.com/user-attachments/assets/1fb36611-f17a-4f5e-8f03-655dee137bc5" />

****Xin hãy lưu ý: Tôi sử dụng claude kết hợp với IDA để phân tích...****

Vì đây là sửa trực tiếp vào một binary đang được Xgpro dùng để lập trình chip thật — sai sót có thể làm hỏng file, crash Xgpro, hoặc tệ hơn là ghi sai tham số vào chip thật.

Vài giới hạn quan trọng phát hiện được khi phân tích:

1. **Sửa/xoá 1 variant chip trong 1 family có sẵn** → an toàn, làm được tốt (sửa tên/PageSize/SpareSize... tại chỗ, hoặc xoá bằng cách hoán đổi với phần tử cuối rồi giảm count — không cần thay đổi kích thước file).
2. **Thêm variant mới vào 1 family có sẵn** → làm được nhưng phức tạp hơn: phải append dữ liệu vào cuối file và cập nhật lại con trỏ + count trong struct family (không sửa tại chỗ được vì hết chỗ trống).
3. **Thêm hẳn 1 family (hãng chip) mới** → **không an toàn** nếu chỉ sửa data — con số `173` (tổng số family) bị hard-code cứng ngay trong code máy đã biên dịch của cả 5 hàm export (`GetDllInfo`, `GetIcMFC`...), không phải đọc từ biến. Muốn thêm family thật sự cần vá luôn code máy (patch instruction), rủi ro cao hơn hẳn.
4. Nhiều byte cuối mỗi record (ví dụ offset 0x5C–0x67, và sau offset 108) tôi **chưa giải mã được ý nghĩa** — có thể là tham số thuật toán/điện áp quan trọng. Nếu sửa nhầm những byte này có thể khiến Xgpro ghi sai vào chip thật.

Kết quả test hoàn hảo (528→528 entries, edit/delete/clone-add đều đúng, family khác không đổi 1 byte). Giờ kiểm tra bước quan trọng nhất: **file đã sửa có còn load được như DLL thật không**.Đã build xong và test trên bản sao thật của `InfoIC2Plus.dll` (không đụng file gốc). 3 file, để cùng thư mục:

- **`infoic2plus_lib.py`** — thư viện lõi (bắt buộc phải có, hai file dưới đều import từ đây)
- **`edit_infoic2plus_cli.py`** — công cụ dòng lệnh
- **`edit_infoic2plus_gui.py`** — giao diện desktop (Tkinter, chạy `python edit_infoic2plus_gui.py InfoIC2Plus.dll`)

**Demo:** sửa 1 chip (đổi PageSize+tên), xoá 1 chip, thêm 1 chip mới (clone từ chip có sẵn), lưu file → rồi **nạp file đã sửa bằng chính `LoadLibrary` của Windows (qua PowerShell 32-bit + P/Invoke)**, gọi thẳng `GetDllInfo`/`GetMfcStru` như Xgpro thật sự gọi. Kết quả: load OK, `magic=100`, `count=173` y hệt bản gốc, đọc đúng dữ liệu đã sửa. Family không đụng tới thì khớp 100% từng byte với bản gốc.

Giới hạn cần nhớ khi dùng:
- Chỉ sửa/thêm/xoá **chip trong 1 hãng (family) có sẵn** — không thêm được hãng mới (do số 173 bị hard-code trong code máy của DLL).
- Khi **thêm chip mới**, dùng lệnh `clone-add` (không phải `blank-add`) — nó copy nguyên 116 byte của 1 chip tương tự rồi chỉ ghi đè tên/field bạn chỉ định, giữ nguyên các byte cuối record còn chưa giải mã được ý nghĩa (rất có thể là tham số thuật toán ghi thật).
- Tên chip tối đa 63 ký tự (dài hơn sẽ đè lên vùng PageSize/SpareSize...).
- Mặc định **không ghi đè file gốc** — luôn lưu ra file `.edited.dll` mới; muốn ghi đè phải bật `--overwrite` (CLI) hoặc "Save (overwrite)" (GUI), lúc đó vẫn tự backup bản gốc kèm timestamp trước khi ghi.
