#include "CppASTScanner.h"

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <tree_sitter/api.h>

extern "C" const TSLanguage *tree_sitter_cpp();

namespace {

std::string read_file(const std::string& path){
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss; ss<<in.rdbuf();
    return ss.str();
}

std::string trim(const std::string& s){
    size_t i=0,j=s.size();
    while(i<j && std::isspace((unsigned char)s[i]))++i;
    while(j>i && std::isspace((unsigned char)s[j-1]))--j;
    return s.substr(i,j-i);
}

std::string node_text(TSNode n, const std::string& src){
    uint32_t a=ts_node_start_byte(n), b=ts_node_end_byte(n);
    if(b>src.size()) b=(uint32_t)src.size();
    if(a>b) a=b;
    return std::string(src.data()+a, src.data()+b);
}

std::string base_name_of(const std::string& s){
    if(s.empty()) return {};
    size_t i=s.size();
    while(i>0 && !std::isalnum((unsigned char)s[i-1]) && s[i-1]!='_') --i;
    size_t e=i;
    while(i>0 && (std::isalnum((unsigned char)s[i-1]) || s[i-1]=='_')) --i;
    return s.substr(i, e-i);
}

}

namespace analyzers {

std::vector<AstSymbol> CppASTScanner::collectSymbols(const std::string& path){
    std::vector<AstSymbol> out;
    std::string code = read_file(path);
    if(code.empty()) return out;

    TSParser* parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_cpp());
    TSTree* tree = ts_parser_parse_string(parser, nullptr, code.c_str(), (uint32_t)code.size());
    if(!tree){ ts_parser_delete(parser); return out; }

    TSNode root = ts_tree_root_node(tree);
    std::vector<TSNode> stack; stack.push_back(root);

    while(!stack.empty()){
        TSNode n = stack.back(); stack.pop_back();
        const char* t = ts_node_type(n);

        if(std::strcmp(t,"call_expression")==0){
            TSNode fn = ts_node_child_by_field_name(n, "function", 8);
            TSNode args = ts_node_child_by_field_name(n, "arguments", 9);
            std::string callee_full, callee_base, first_arg;

            if(!ts_node_is_null(fn)){
                callee_full = trim(node_text(fn, code));
                callee_base = base_name_of(callee_full);
            }else{
                std::string seg = trim(node_text(n, code));
                auto p = seg.find('(');
                if(p!=std::string::npos) callee_full = trim(seg.substr(0,p));
                callee_base = base_name_of(callee_full);
            }

            if(!ts_node_is_null(args)){
                uint32_t nc = ts_node_named_child_count(args);
                if(nc>0){
                    TSNode a0 = ts_node_named_child(args, 0);
                    if(!ts_node_is_null(a0)){
                        std::string a0txt = trim(node_text(a0, code));
                        if(!a0txt.empty()){
                            if(a0txt.size()>=2 && (a0txt.front()=='"' || a0txt.front()=='\'')){
                                char q=a0txt.front();
                                size_t i=1;
                                std::string v;
                                while(i<a0txt.size()){
                                    char c=a0txt[i++];
                                    if(c=='\\' && i<a0txt.size()){ v.push_back(a0txt[i++]); continue; }
                                    if(c==q) break;
                                    v.push_back(c);
                                }
                                first_arg = v;
                            }else{
                                first_arg = a0txt;
                            }
                        }
                    }
                }
            }

            TSPoint p = ts_node_start_point(n);
            size_t line = (size_t)p.row + 1;

            if(!callee_full.empty()){
                AstSymbol s;
                s.filePath = path;
                s.line = line;
                s.lang = "cpp";
                s.callee_full = callee_full;
                s.callee_base = callee_base.empty()? callee_full : callee_base;
                s.first_arg = first_arg;
                out.push_back(std::move(s));
            }
        }

        uint32_t c = ts_node_child_count(n);
        for(uint32_t i=0;i<c;++i){
            TSNode ch = ts_node_child(n,i);
            if(ts_node_is_null(ch)) continue;
            if(!ts_node_is_named(ch)) continue;
            stack.push_back(ch);
        }
    }

    ts_tree_delete(tree);
    ts_parser_delete(parser);
    return out;
}

}
