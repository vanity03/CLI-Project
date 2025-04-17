# https://mnk.sk/fake/ - Zoznam fake domen


file_path = ""

with open(f"{file_path}", "r") as f:
    lines = sorted(set(line.strip() for line in f))

with open(f"{file_path}", "w") as f:
    f.write("\n".join(lines) + "\n") 

