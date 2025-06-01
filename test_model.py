from app.model import CitizenCreate, CitizenDisplay # Đảm bảo đường dẫn import đúng

# Test CitizenCreate
try:
    # Dữ liệu hợp lệ
    valid_data = {
        "citizen_id": "CD001",
        "name": "Test User",
        "dob": "15/05/1985",
        "address": "1 Test Street"
    }
    citizen_c = CitizenCreate(**valid_data)
    print("CitizenCreate valid data OK:", citizen_c.model_dump_json(indent=2)) # Pydantic V2+ dùng model_dump_json
    # print("CitizenCreate valid data OK:", citizen_c.json(indent=2)) # Pydantic V1 dùng .json()

    # Dữ liệu thiếu trường bắt buộc
    invalid_data_missing = {
        "name": "Test User 2",
        "dob": "10/10/1990",
        "address": "2 Test Avenue"
    }
    # citizen_c_invalid = CitizenCreate(**invalid_data_missing) # Sẽ báo lỗi
except Exception as e:
    print("\nError with CitizenCreate (missing field):", e)

# Test CitizenDisplay
display_data = {
    "citizen_id": "CD002",
    "name": "Display User",
    "dob": "20/12/2000",
    "address": "3 Display Road"
}
citizen_d = CitizenDisplay(**display_data)
print("\nCitizenDisplay OK:", citizen_d.model_dump_json(indent=2)) # Pydantic V2+
# print("\nCitizenDisplay OK:", citizen_d.json(indent=2)) # Pydantic V1

# Nếu muốn test Config.from_attributes (hoặc orm_mode)
class SomeObject:
    def __init__(self, citizen_id, name, dob, address):
        self.citizen_id = citizen_id
        self.name = name
        self.dob = dob
        self.address = address

obj_data = SomeObject("CD003", "Object User", "05/07/1970", "4 Object Lane")
try:
    citizen_d_from_obj = CitizenDisplay.model_validate(obj_data) # Pydantic V2+
    # citizen_d_from_obj = CitizenDisplay.from_orm(obj_data) # Pydantic V1
    print("\nCitizenDisplay from object OK:", citizen_d_from_obj.model_dump_json(indent=2))
except Exception as e:
    print(f"\nError creating CitizenDisplay from object: {e}")