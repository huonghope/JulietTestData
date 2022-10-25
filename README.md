Run command

```python
  python3 runCompleteAnalysis.py 
```
## Thông tin 1 số file: 
- existingIssues.xml: file này để tổng hợp các thông tin của các hàm _bad (Những hàm mang lỗ hõng)
  + Sẽ được đánh dáu với label là 0:
  + Line cụ thể của lỗ hỏng sẽ cần matching tới file manifest.xml (nằm trong /tmpData folder)
- manifest.xml: Đây là file lưu lại thông tin danh sách cái file 
  + Tên file
  + Line lỗ hỏng tương tứng với file
  + Tuy nhiên sẽ có 1 số lỗ hỏng đặc biệt: gồm nhiều file gộp lại (Khó quá có thể skip để làm thử công)

- folder tmpData: sẽ lưu lại kết quả của
** Có thể tham khảo qua file copyCodeToExcel.py
- Flow cơ bản: đọc bài tổng hợp function (startLine, endLine) => đọc ngược lại file theo line => copy sang excel => cộng thêm 1 số thông tin đi kèm
