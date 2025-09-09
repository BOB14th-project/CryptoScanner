# CryptoScanner

### 💻 GUI Beta (2025.09.10. ver)
<img width="1918" height="875" alt="image" src="https://github.com/user-attachments/assets/d3ccd4b2-ff03-479c-9be0-2b1bb529ae55" />

### 🔧 첫 설치
``` bash
git clone https://github.com/BOB14th-project/CryptoScanner.git
sudo apt install qtbase5-dev qt5-qmake
cd CryptoScanner
qmake CryptoScanner.pro
make -j"$(nproc)"
```

### 🔧 패키지 설치
``` bash
sudo apt install -y jadx || true // JADX 패키지 미설치 시 실행
```

### 🔧 재빌드
``` bash
make rebuild
```

### 🚀 CryptoScanner 사용 방법
1. GUI 상단에서 현재 설치된 도구 배지를 확인 (javap/jadx/python3/clang)
2. `파일 선택` 혹은 `폴더 선택`을 눌러 대상 지정 → 필요 시 하위 폴더 포함 체크
3. `스캔 버튼` 클릭 → 하단 표 확인
4. 행을 더블클릭 → 오프셋 주변 바이트를 헥스 덤프로 확인 가능
5. `결과 저장` → `./result/crypto_scan_YYYYMMDD_HHmmss.csv` 저장

### 🔍`patterns.json` 정적(패턴) 탐지 로직
1. 문자열 정규식(regex) : 파일 내 추출된 ASCII 문자열에 대해 정규식을 적용
2. 바이트 시그니처(bytes) : OID DER 인코딩, 곡선 소수/파라미터, 상수(basepoint) 등 바이트열 매칭
3. AST/바이트코드: `Java` / `Python` / `C/C++` / `JAR/CLASS`
