라즈베리파이에서 Flask 서버 실행하는 방법
🔹 1️⃣ Python & pip 준비
sudo apt update && sudo apt upgrade -y
sudo apt install python3 python3-pip -y

🔹 2️⃣ 프로젝트 폴더로 이동

예를 들어 서버 코드가 /home/pi/apex_server 안에 있다면:

cd /home/pi/apex_server

🔹 3️⃣ 필요한 라이브러리 설치

requirements.txt 파일이 있다면:

pip3 install -r requirements.txt


(없으면 pip3 install flask flask_sqlalchemy flask_socketio eventlet flask_cors ... 이런 식으로 직접 설치해도 됨)

🔹 4️⃣ 데이터베이스 초기화 (Flask-Migrate 사용 시)
flask db init
flask db migrate -m "init"
flask db upgrade


만약 이 단계에서 flask 명령이 인식되지 않으면
python3 -m flask db init 이런 식으로 해도 돼.

🔹 5️⃣ 서버 실행

일반 실행:

python3 server.py


서버가 계속 켜져 있게 하려면 (터미널 닫아도):

nohup python3 server.py &


→ 실행 후 Ctrl + C 눌러도 계속 백그라운드에서 돌아감.
→ 로그는 nohup.out 파일에 저장됨.

🔹 6️⃣ 실행 확인

같은 네트워크에서:

http://라즈베리파이IP:5000


포트포워딩 되어 있다면 외부에서도:

http://공인IP:5000


또는

http://apexbeta.duckdns.org:5000

🔹 7️⃣ 서버 자동 실행 (선택)

라즈베리파이 재부팅 시 자동으로 서버가 켜지게 하려면:

crontab -e


맨 아래에 추가:

@reboot cd /home/pi/apex_server && nohup python3 server.py &
