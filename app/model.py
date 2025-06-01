from pydantic import BaseModel, Field # Field dùng để thêm ví dụ, validation,...
from typing import Optional # Dùng nếu có trường tùy chọn

# Model cơ sở chứa các trường chung, không bao gồm citizen_id vì nó sẽ
# được cung cấp riêng khi tạo hoặc đã có sẵn khi hiển thị.
class CitizenBase(BaseModel):
    name: str = Field(..., example="Nguyen Van A", description="Họ và tên đầy đủ của công dân")
    dob: str = Field(..., example="01/01/1990", description="Ngày sinh theo định dạng DD/MM/YYYY")
    address: str = Field(..., example="123 Đường ABC, Phường XYZ, Quận 1, TP. HCM", description="Địa chỉ thường trú")
    # Bạn có thể thêm các trường khác ở đây nếu muốn
    # Ví dụ:
    # email: Optional[str] = Field(None, example="nguyenvana@example.com", description="Địa chỉ email (tùy chọn)")
    # phone_number: Optional[str] = Field(None, example="0901234567", description="Số điện thoại (tùy chọn)")

# Model dùng khi tạo mới một công dân (request body cho endpoint /register)
# Sẽ kế thừa từ CitizenBase và thêm trường citizen_id (bắt buộc khi tạo)
class CitizenCreate(CitizenBase):
    citizen_id: str = Field(..., example="CD001234567", description="Mã số định danh công dân duy nhất")

# Model dùng để hiển thị thông tin công dân (response body cho endpoint /lookup)
# Cũng kế thừa từ CitizenBase và có citizen_id
class CitizenDisplay(CitizenBase):
    citizen_id: str = Field(..., example="CD001234567")

    # Sử dụng Pydantic V2 orm_mode (trước đây là orm_mode trong V1) để tương thích với đối tượng ORM (nếu có)
    # Hoặc để dễ dàng tạo instance từ dict (ví dụ, từ kết quả DB)
    class Config:
        # orm_mode = True # Cho Pydantic V1
        from_attributes = True # Cho Pydantic V2+
        # (Pydantic V2 là from_attributes, V1 là orm_mode. Kiểm tra phiên bản Pydantic bạn dùng)
        # Nếu bạn dùng FastAPI >= 0.100.0, Pydantic V2 có thể là mặc định.


# Model cho thông báo phản hồi đơn giản
class MessageResponse(BaseModel):
    message: str = Field(..., example="Thao tác thành công")

# Model cho phản hồi lỗi (FastAPI sẽ tự động xử lý nhiều trường hợp, nhưng có thể bạn muốn định nghĩa riêng)
class ErrorResponse(BaseModel):
    detail: str = Field(..., example="Thông tin không hợp lệ")