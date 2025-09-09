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


### 📁 파일 별 역할
| 경로 | 역할 |
|---|:---:|
| `CryptoScanner.pro` | qmake 프로젝트 파일, `rebuild` 타깃 등 빌드 설정 포함 |
| `gui_main_linux.cpp` | GUI, 파일/폴더 선택, 하위 폴더 포함 옵션, 스캔 실행, 결과 테이블/CSV 내보내기, 헥스 프리뷰, 툴 배지(javap/jadx/python3/clang) 표시 |
| `CryptoScanner.h/.cpp` | 경로 단위 스캔, 결과 수집/정규화, CSV 저장, 환경변수(`CRYPTO_PATTERNS`, `CRYPTO_SCANNER_JADX_MAXMB`) 처리, 파일 유형별 라우팅과 심각도 규칙 적용 |
| `FileScanner.h/.cpp` | 파일 열기/부분 읽기, 문자열 추출, 바이트 시그니처/정규식 매칭, 확장자·매직 넘버 기반 타입 식별, ZIP/JAR 엔트리 나열 및 엔트리 단위 스캔, 헥스 프리뷰(오프셋 주변 바이트) 제공 |
| `PatternLoader.h/.cpp` | `patterns.json` 로딩/검증, 정규식 컴파일 옵션 처리 |
| `PatternDefinitions.h/.cpp` | 호환성/참고용으로 유지될 수 있음(아직 큰 역할 없음, 풀백으로 사용 고민) |
| `JavaASTScanner.h/.cpp` | Java 소스 코드 정적 규칙 탐지 |
| `JavaBytecodeScanner.h/.cpp` | `JAR/CLASS` 바이트코드 분석 |
| `PythonASTScanner.h/.cpp` | Python 소스 코드 정적 규칙 탐지 |
| `CppASTScanner.h/.cpp` | C/C++ 소스 코드 정적 규칙 탐지 |
| `patterns.json` | 탐지 규칙 정의(정규식/바이트/AST), 재빌드 없이 편집 가능 |
| `result/` | CSV 결과 저장 디렉터리(실행 시 자동 생성) |
