# Project Installation Guide

1. **Clone the repository:**
```bash
git clone https://github.com/vanity03/CLI-Project.git
cd CLI-Project
```

2. **Activate venv and Install the requirements**
```bash
python -m venv venv
venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
```

```bash
pip install -r requirements.txt
```

3. **Start the application + example domain**
```bash
python main.py upjs.sk
```

4. **A warning usually appears about feature names after running the code, that is also due to Random Forest working a bit different than other models. This warning is harmless and does not influence the output.**