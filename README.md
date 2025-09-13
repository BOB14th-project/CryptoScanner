# CryptoScanner

### 💻 GUI Beta (2025.09.13. ver)
<img width="1728" height="1044" alt="스크린샷 2025-09-13 20 13 42" src="https://github.com/user-attachments/assets/b2fc2b66-91e3-49dc-836f-e5bdf873d896" />


### 🔧 첫 설치
``` bash
git clone https://github.com/BOB14th-project/CryptoScanner.git
sudo apt install build-essential qtbase5-dev qt5-qmake libssl-dev
cd CryptoScanner
qmake CryptoScanner.pro
make -j"$(nproc)"
```


### 🔧 재빌드
``` bash
make rebuild
```


### 🚀 CryptoScanner 사용 방법
1. `파일 선택` 혹은 `폴더 선택`을 눌러 대상 지정 → 필요 시 하위 폴더 포함 체크
2. `스캔 버튼` 클릭 → 하단 표 확인
3. 행을 더블클릭 → 오프셋 주변 바이트를 헥스 덤프로 확인 가능
4. `결과 저장` → `./result/YYYYMMDD_HHmmss.csv` 저장


### 🔍`patterns.json` 정적(패턴) 탐지 로직
1. 문자열 정규식(regex) : 파일 내 추출된 ASCII 문자열에 대해 정규식을 적용
2. 바이트 시그니처(bytes) : OID DER 인코딩, 곡선 소수/파라미터, 상수(basepoint) 등 바이트열 매칭
3. AST/바이트코드: `Java` / `Python` / `C/C++` / `JAR/CLASS`

### 📈 정적(패턴) 탐지 Flow Chart
<img width="7585" height="4697" alt="static_flowchart" src="https://github.com/user-attachments/assets/bde8886e-5d08-4e06-b74a-765b0b6995de" />


### 📁 파일 별 역할
| 경로 | 역할 |
|:---:|---|
| `test_*/` | 테스트 파일 |
| `third_party/` | miniz 라이브러리, tree-sitter 라이브러리 |
| `result/` | CSV 결과 저장 디렉터리(실행 시 자동 생성) |
| `patterns.json` | 탐지 규칙 정의(정규식/바이트/AST), 재빌드 없이 편집 가능 |
| `CryptoScanner.pro` | qmake 프로젝트 파일, `rebuild` 타깃 등 빌드 설정 포함 |
| `gui_main_linux.cpp` | GUI |
| `CryptoScanner.h/.cpp` | 경로 단위 스캔, 결과 수집/정규화, CSV 저장 |
| `FileScanner.h/.cpp` | 파일 열기/부분 읽기, 문자열 추출, 바이트 시그니처/정규식 매칭  |
| `PatternLoader.h/.cpp` | `patterns.json` 로딩/검증, 정규식 컴파일 옵션 처리 |
| `PatternDefinitions.h/.cpp` | 아직 큰 역할 없음, 풀백으로 사용 고민(현재 AST 풀백 코드 有) |
| `ASTSymbol.h` | AST Symbol tree-sitter을 통한 함수(심볼)에서 정규식 매칭 |
| `JavaASTScanner.h/.cpp` | Java 소스 코드 정적 규칙 탐지 |
| `JavaBytecodeScanner.h/.cpp` | `JAR/CLASS` 바이트코드 분석 |
| `PythonASTScanner.h/.cpp` | Python 소스 코드 정적 규칙 탐지 |
| `CppASTScanner.h/.cpp` | C/C++ 소스 코드 정적 규칙 탐지 |
