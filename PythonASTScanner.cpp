#include "PythonASTScanner.h"
#include "PatternLoader.h"

#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

namespace analyzers {

static std::string writeTempPy(){
    const std::string tmpRoot = CryptoScanner::makeTempDir();
    if(tmpRoot.empty()) return {};
    const std::string py = tmpRoot + "/py_ast_analyzer.py";
    std::ofstream o(py);
    o <<
R"(import ast, sys, json, re

RULES = json.loads(sys.stdin.read())

def fullname(node):
    if isinstance(node, ast.Attribute):
        base = fullname(node.value)
        if base: return base + "." + node.attr
        return node.attr
    elif isinstance(node, ast.Name):
        return node.id
    return ""

def get_kw(kws, key):
    for kw in kws:
        if isinstance(kw, ast.keyword) and kw.arg==key:
            return kw
    return None

class V(ast.NodeVisitor):
    def __init__(self): self.out=[]
    def visit_Call(self, node: ast.Call):
        fn = fullname(node.func)
        def arg_text(idx):
            if idx < len(node.args):
                a=node.args[idx]
                if isinstance(a, ast.Constant) and isinstance(a.value, str):
                    return a.value
                if isinstance(a, ast.Constant) and isinstance(a.value, int):
                    return str(a.value)
            return ""
        for r in RULES:
            if r.get("lang")!="python": continue
            kind = r.get("kind","")
            cal  = r.get("callee","")
            msg  = r.get("message","rule")
            sev  = r.get("severity","med")
            if kind=="call_fullname" and fn==cal:
                self.out.append((node.lineno, msg, sev, cal))
            elif kind=="call_fullname+arg" and fn==cal:
                s = arg_text(0)
                arg_rx = r.get("arg_regex","")
                if arg_rx and re.search(arg_rx, s or "", re.I):
                    self.out.append((node.lineno, msg, sev, s))
            elif kind=="call_fullname+intarg" and fn==cal:
                s = arg_text(r.get("arg_index",0))
                if s.isdigit():
                    self.out.append((node.lineno, msg, sev, s))
            elif kind=="call_fullname+kwcheck" and fn==cal:
                kw = get_kw(node.keywords, r.get("kw","mode"))
                if kw and isinstance(kw.value, ast.Attribute):
                    kval = fullname(kw.value)
                elif kw and isinstance(kw.value, ast.Name):
                    kval = kw.value.id
                else:
                    kval = ""
                if re.search(r.get("kw_value_regex",""), kval or "", re.I):
                    self.out.append((node.lineno, msg, sev, kval))
        self.generic_visit(node)

def main():
    p = sys.argv[1]
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()
    try:
        t = ast.parse(src, filename=p)
    except Exception:
        return
    v=V(); v.visit(t)
    for (ln, msg, sev, ev) in v.out:
        sys.stdout.write(f"DETECT\t{ln}\t{msg}\t{sev}\t{ev}\n")

if __name__=="__main__": main()
)";
    o.close();
    return py;
}

std::vector<Detection> PythonASTScanner::scanFile(const std::string& path){
    std::vector<Detection> out;
    if(!CryptoScanner::toolExists("python3")) return out;

    auto LR = pattern_loader::loadFromJson();
    const std::string script = writeTempPy();
    if(script.empty()){
        return out;
    }

    const std::string tmpJson = fs::path(script).parent_path().string() + "/rules.json";
    {
        std::ofstream j(tmpJson);
        j << "[\n";
        bool first=true;
        for(const auto& r: LR.astRules){
            if(r.lang!="python") continue;
            if(!first) j << ",\n";
            first=false;
            j << "  " << r.toJson();
        }
        j << "\n]\n";
    }
    std::string cmd = "cat " + CryptoScanner::shellQuote(tmpJson) + " | python3 "
                    + CryptoScanner::shellQuote(script) + " " + CryptoScanner::shellQuote(path) + " 2>/dev/null";
    std::string outText;
    if(CryptoScanner::runCommandText(cmd, outText)){
        std::istringstream iss(outText);
        while(true){
            std::string L; if(!std::getline(iss, L)) break;
            if(L.rfind("DETECT\t",0)==0){
                std::istringstream ls(L);
                std::string tmp, msg, ev, sev; size_t line=0;
                std::getline(ls, tmp, '\t'); // DETECT
                std::getline(ls, tmp, '\t'); line = (size_t)std::stoul(tmp);
                std::getline(ls, msg, '\t');
                std::getline(ls, sev, '\t');
                std::getline(ls, ev,  '\t');
                out.push_back({ path, line, msg, ev, "ast", sev.empty()? "med": sev });
            }
        }
    }
    CryptoScanner::removeDirRecursive(fs::path(script).parent_path().string());
    return out;
}

} // namespace analyzers
