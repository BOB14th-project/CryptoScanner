#include "CryptoScanner.h"
#include "PatternLoader.h"

#ifdef _WIN32
#error "gui_main_linux.cpp is intended for non-Windows builds only."
#endif

#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QLabel>
#include <QLineEdit>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QMessageBox>
#include <QCheckBox>
#include <QDateTime>
#include <QTextStream>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QDesktopServices>
#include <QUrl>
#include <QDir>
#include <QDialog>

#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

static bool checkCmdExists(const QString& name){
    QString program = "sh";
    QStringList args;
    args << "-c" << QString("command -v %1 >/dev/null 2>&1").arg(name);
    int code = QProcess::execute(program, args);
    return (code==0);
}

static QString humanizeEvidence(const std::string& matchString, const std::string& evidenceType){
    const std::string& s = matchString;
    auto hexLike = [&](){
        if(s.empty()) return false;
        auto isHex = [](char c){
            return (c>='0'&&c<='9')||(c>='A'&&c<='F')||(c>='a'&&c<='f');
        };
        return std::all_of(s.begin(), s.end(), isHex) && (s.size()%2==0) && s.size()>=8;
    };
    if(evidenceType=="oid" || evidenceType=="curve" || evidenceType=="prime" || (evidenceType=="bytes" && hexLike())){
        std::ostringstream os;
        os << "바이트 매칭: ";
        size_t show = std::min<size_t>(s.size(), 32);
        for(size_t i=0;i<show;i+=2){
            os << s[i] << s[i+1];
            if(i+2<show) os << ' ';
        }
        if(s.size() > show) os << " …";
        return QString::fromStdString(os.str());
    }
    if(evidenceType=="ast")   return QString("AST 근거: %1").arg(QString::fromStdString(s));
    if(evidenceType=="x509")  return QString("X.509 근거: %1").arg(QString::fromStdString(s));
    if(evidenceType=="bytecode") return QString("바이트코드 근거: %1").arg(QString::fromStdString(s));
    return QString("정규식 매칭: %1").arg(QString::fromStdString(s));
}

struct ToolStatus { bool javap=false, jadx=false, python3=false, clang=false; QString patternFile; };

static ToolStatus detectTools(){
    ToolStatus t;
    t.javap   = checkCmdExists("javap");
    t.jadx    = checkCmdExists("jadx");
    t.python3 = checkCmdExists("python3");
    t.clang   = checkCmdExists("clang");
    QByteArray env = qgetenv("CRYPTO_PATTERNS");
    if(!env.isEmpty()) t.patternFile = QString::fromUtf8(env);
    else t.patternFile = "patterns.json";
    return t;
}

static QLabel* makeBadge(const QString& label, bool ok){
    QLabel* w = new QLabel(QString("%1: %2").arg(label).arg(ok? "OK":"미설치"));
    w->setContentsMargins(10,4,10,4);
    w->setAlignment(Qt::AlignCenter);
    w->setStyleSheet(QString("QLabel{border-radius:10px; color:%1; background:%2; font-weight:600;}")
                     .arg(ok? "#0a3d0a":"#611")
                     .arg(ok? "#CFF7CF":"#F8D7DA"));
    return w;
}

static QLabel* makePathChip(const QString& path){
    QString base = QFileInfo(path).fileName();
    QLabel* w = new QLabel(QString("패턴: %1").arg(base));
    w->setToolTip(path);
    w->setContentsMargins(10,4,10,4);
    w->setAlignment(Qt::AlignCenter);
    w->setStyleSheet("QLabel{border-radius:10px; color:#0B2E4A; background:#D1ECF1; font-weight:600;}");
    return w;
}

static QString hexDump(const QByteArray& a){
    std::ostringstream os;
    os << std::uppercase << std::hex << std::setfill('0');
    for (int i=0;i<a.size();++i){
        os << std::setw(2) << (static_cast<unsigned char>(a[i]) & 0xFF);
        if(i+1<a.size()) os << ' ';
    }
    return QString::fromStdString(os.str());
}
static bool readSlice(const QString& path, std::size_t off, std::size_t len, QByteArray& out){
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)) return false;
    if(off > static_cast<std::size_t>(f.size())) return false;
    if(!f.seek(static_cast<qint64>(off))) return false;
    out = f.read(static_cast<qint64>(len));
    return out.size()>0;
}

class MainWindow : public QWidget {
    Q_OBJECT
public:
    MainWindow(QWidget* parent=nullptr) : QWidget(parent){
        setWindowTitle("Crypto Scanner");
        resize(1220, 760);

        setStyleSheet(R"CSS(
            QTableWidget {
                background-color:#1f2330;
                alternate-background-color:#252a3a;
                color:#e9edf1;
                gridline-color:#3a3f5c;
                selection-background-color:#3b82f6;
                selection-color:#ffffff;
            }
            QHeaderView::section{
                background:#2b3045;
                color:#e9edf1;
                padding:6px;
                border:0;
            }
        )CSS");

        auto tools = detectTools();
        auto topBar = new QHBoxLayout;
        topBar->setSpacing(8);
        topBar->addWidget(makeBadge("javap", tools.javap));
        topBar->addWidget(makeBadge("jadx", tools.jadx));
        topBar->addWidget(makeBadge("python3", tools.python3));
        topBar->addWidget(makeBadge("clang", tools.clang));
        topBar->addWidget(makePathChip(tools.patternFile));
        topBar->addStretch();

        auto pathRow = new QHBoxLayout;
        pathEdit = new QLineEdit;
        pathEdit->setPlaceholderText("분석할 파일 또는 폴더를 선택하세요…");
        pathEdit->setReadOnly(true);
        auto btnFile = new QPushButton("파일 선택");
        auto btnFolder = new QPushButton("폴더 선택");
        recurCheck = new QCheckBox("하위 폴더 포함");
        scanBtn  = new QPushButton("스캔");
        resetBtn = new QPushButton("초기화");
        exportBtn= new QPushButton("결과 저장");
        pathRow->addWidget(pathEdit,1);
        pathRow->addWidget(btnFile);
        pathRow->addWidget(btnFolder);
        pathRow->addWidget(recurCheck);
        pathRow->addWidget(scanBtn);
        pathRow->addWidget(resetBtn);
        pathRow->addWidget(exportBtn);

        table = new QTableWidget(0, 6);
        table->setAlternatingRowColors(true);
        table->setHorizontalHeaderLabels({"파일(항목)","오프셋","탐지 알고리즘","매칭 근거","근거 유형","심각도"});
        table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
        table->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
        table->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);

        connect(btnFile,&QPushButton::clicked,this,[this](){
            QString f = QFileDialog::getOpenFileName(this,"파일 선택");
            if(!f.isEmpty()){ selectedPath=f; isDirectory=false; pathEdit->setText(f); }
        });
        connect(btnFolder,&QPushButton::clicked,this,[this](){
            QFileDialog dlg(this, "폴더 선택");
            dlg.setFileMode(QFileDialog::Directory);
            dlg.setOption(QFileDialog::ShowDirsOnly, true);
            dlg.setOption(QFileDialog::DontUseNativeDialog, true);
            if(dlg.exec()==QDialog::Accepted){
                QString d = dlg.selectedUrls().value(0).toLocalFile();
                if(!d.isEmpty()){ selectedPath=d; isDirectory=true; pathEdit->setText(d); }
            }
        });
        connect(scanBtn,&QPushButton::clicked,this,&MainWindow::onScan);
        connect(resetBtn,&QPushButton::clicked,this,&MainWindow::onClear);
        connect(exportBtn,&QPushButton::clicked,this,&MainWindow::onExportCsvAuto);
        connect(table,&QTableWidget::cellDoubleClicked,this,&MainWindow::openDetailForRow);

        auto root = new QVBoxLayout;
        root->addLayout(topBar);
        root->addLayout(pathRow);
        root->addWidget(table,1);
        setLayout(root);
    }

private slots:
    void onClear(){
        selectedPath.clear();
        pathEdit->clear();
        table->setRowCount(0);
        results.clear();
    }

    void onScan(){
        if(selectedPath.isEmpty()){
            QMessageBox::warning(this,"경고","먼저 파일 또는 디렉터리를 선택하세요.");
            return;
        }
        table->setRowCount(0);
        results.clear();

        try{
            CryptoScanner scanner;
            std::vector<Detection> det;
            if(isDirectory){
                if(recurCheck->isChecked()){
                    det = scanner.scanPathRecursive(selectedPath.toStdString());
                }else{
                    QDir dir(selectedPath);
                    const QFileInfoList list = dir.entryInfoList(QDir::Files | QDir::NoSymLinks, QDir::Name);
                    for(const QFileInfo& fi : list){
                        auto one = scanner.scanFileDetailed(fi.absoluteFilePath().toStdString());
                        det.insert(det.end(), one.begin(), one.end());
                    }
                }
            }else{
                det = scanner.scanFileDetailed(selectedPath.toStdString());
            }
            populate(det);
        }catch(const std::exception& e){
            QMessageBox::critical(this,"스캔 오류", QString("예외: %1").arg(e.what()));
        }catch(...){
            QMessageBox::critical(this,"스캔 오류","알 수 없는 예외가 발생했습니다.");
        }
    }

    void onExportCsvAuto(){
        if(results.empty()){
            QMessageBox::information(this,"내보내기","먼저 스캔을 실행해 주세요.");
            return;
        }
        const QString appDir = QCoreApplication::applicationDirPath();
        const QString resultDir = QDir(appDir).absoluteFilePath("result");
        QDir().mkpath(resultDir);
        const QString fileName = "crypto_scan_" + QDateTime::currentDateTime().toString("yyyyMMdd_HHmmss") + ".csv";
        const QString path = QDir(resultDir).absoluteFilePath(fileName);

        if(exportCsv(path)){
            QMessageBox::information(this,"완료","저장됨:\n" + path);
        }else{
            QMessageBox::warning(this,"실패","CSV 저장에 실패했습니다:\n" + path);
        }
    }

    void openDetailForRow(int row, int){
        if(row<0 || row>=table->rowCount()) return;
        QString f = table->item(row,0)->data(Qt::UserRole).toString();
        std::size_t off = table->item(row,1)->data(Qt::UserRole).toULongLong();
        int matchLen = table->item(row,3)->data(Qt::UserRole).toInt();

        QByteArray pre, mid, post;
        readSlice(f, (off>=16?off-16:0), (off>=16?16:off), pre);
        readSlice(f, off, std::max(16, matchLen>0?matchLen:16), mid);
        readSlice(f, off+(matchLen>0?matchLen:16), 16, post);

        QString msg;
        msg += "파일: " + f + "\n";
        msg += QString("오프셋: %1 (0x%2)\n").arg(QString::number(off)).arg(QString::number(off,16));
        msg += "탐지 알고리즘: " + table->item(row,2)->text() + "\n";
        msg += "매칭 근거: " + table->item(row,3)->text() + "\n";
        msg += "근거 유형: " + table->item(row,4)->text() + "\n";
        msg += "Severity: " + table->item(row,5)->text() + "\n\n";
        msg += "주변 바이트(16B | 매칭 | 16B):\n";
        msg += hexDump(pre) + " | " + hexDump(mid) + " | " + hexDump(post);
        QMessageBox::information(this,"세부 정보", msg);
    }

private:
    bool exportCsv(const QString& path){
        QFile f(path);
        if(!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
            return false;
        QTextStream ts(&f);
#if QT_VERSION >= QT_VERSION_CHECK(6,0,0)
        ts.setEncoding(QStringConverter::Utf8);
#else
        ts.setCodec("UTF-8");
#endif
        ts << QChar(0xFEFF);

        auto writeRow = [&](QStringList cols){
            for(QString& c : cols){
                if (c.contains('"') || c.contains(',') || c.contains('\n') || c.contains('\r')){
                    c.replace("\"","\"\"");
                    c = "\"" + c + "\"";
                }
            }
            ts << cols.join(",") << "\r\n";
        };

        QStringList headers;
        for (int c=0; c<table->columnCount(); ++c)
            headers << table->horizontalHeaderItem(c)->text();
        writeRow(headers);

        for (int r=0; r<table->rowCount(); ++r){
            QStringList row;
            for (int c=0; c<table->columnCount(); ++c){
                auto *it = table->item(r,c);
                row << (it ? it->text() : "");
            }
            writeRow(row);
        }
        f.close();
        return true;
    }

    void populate(const std::vector<Detection>& det){
        results = det;
        table->setRowCount(static_cast<int>(det.size()));
        for(int i=0;i<table->rowCount();++i){
            const auto& d = det[static_cast<size_t>(i)];
            auto it0 = new QTableWidgetItem(QString::fromStdString(d.filePath));
            it0->setData(Qt::UserRole, QString::fromStdString(d.filePath));
            table->setItem(i,0,it0);

            auto it1 = new QTableWidgetItem(QString::number(d.offset));
            it1->setData(Qt::UserRole, static_cast<qulonglong>(d.offset));
            table->setItem(i,1,it1);

            auto it2 = new QTableWidgetItem(QString::fromStdString(d.algorithm));
            table->setItem(i,2,it2);

            auto pretty = humanizeEvidence(d.matchString, d.evidenceType);
            auto it3 = new QTableWidgetItem(pretty);
            int mlen = 0;
            bool hexLike = true;
            for(char c: d.matchString){ if(!std::isxdigit(static_cast<unsigned char>(c))) { hexLike=false; break; } }
            if(hexLike && (d.matchString.size()%2==0)) mlen = static_cast<int>(d.matchString.size()/2);
            it3->setData(Qt::UserRole, mlen);
            table->setItem(i,3,it3);

            auto it4 = new QTableWidgetItem(QString::fromStdString(d.evidenceType));
            table->setItem(i,4,it4);

            auto it5 = new QTableWidgetItem(QString::fromStdString(d.severity));
            table->setItem(i,5,it5);
        }
        table->resizeRowsToContents();
    }

private:
    QLineEdit   *pathEdit=nullptr;
    QPushButton *scanBtn=nullptr, *resetBtn=nullptr, *exportBtn=nullptr;
    QCheckBox   *recurCheck=nullptr;
    QTableWidget *table=nullptr;

    QString selectedPath;
    bool isDirectory=false;
    std::vector<Detection> results;
};

#include "gui_main_linux.moc"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    MainWindow w;
    w.show();
    return app.exec();
}
