# intrusion-detection-dashboard

How to set up the project.

1. Install python 3.8 or above if not available
2. Create virtual environment name env in the project folder : `python -m venv .venv`
3. Move to the project folder and activate virtual environment :
   - in Mac and Linux :source .venv/bin/activate
   - in Windows : run activate.bat file which is inside \.venv\Scripts folder by running `.venv\Scripts\activate`
4. Install required libraries : `pip3 install -r requirements.txt`
5. After stop the project, deactivate virtual environment : deactivate

Run project

1. `streamlit run home.py`

Save Dependancies

1. Run `pip freeze > requirements.txt` after installing any pip package