file_path = "scripts\\classification\\datasets\\workshop.csv"

with open(f"{file_path}", "r", encoding="utf-8") as file:
    lines = file.readlines()

header = lines[0] 
data_lines = lines[1:] 

sorted_lines = sorted(data_lines, key=lambda x: int(x.strip().split(",")[-1]))

with open(f"{file_path}", "w", encoding="utf-8") as file:
    file.write(header)
    file.writelines(sorted_lines)
