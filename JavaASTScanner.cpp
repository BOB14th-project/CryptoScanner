#include "JavaASTScanner.h"

#include <string>
#include <vector>
#include <cctype>
#include <cstring>
#include <tree_sitter/api.h>

extern "C" const TSLanguage *tree_sitter_java();

namespace {

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

std::string callee_from_segment(const std::string& seg){
    auto p = seg.find('(');
    if(p==std::string::npos) return trim(seg);
    return trim(seg.substr(0,p));
}

std::pair<bool,std::string> first_arg_literal_from_segment(const std::string& seg){
    auto p = seg.find('(');
    if(p==std::string::npos) return {false,{}};
    size_t i=p+1;
    while(i<seg.size() && std::isspace((unsigned char)seg[i])) ++i;
    if(i>=seg.size()) return {false,{}};
    if(seg[i]=='"' || seg[i]=='\''){
        char q=seg[i++];
        std::string v;
        while(i<seg.size()){
            char c=seg[i++];
            if(c=='\\' && i<seg.size()){ v.push_back(seg[i++]); continue; }
            if(c==q) return {true,v};
            v.push_back(c);
        }
        return {false,{}};
    }
    size_t j=i;
    while(j<seg.size() && (std::isalnum((unsigned char)seg[j]) || seg[j]=='_')) ++j;
    if(j>i) return {true, seg.substr(i, j-i)};
    return {false,{}};
}

}

namespace analyzers {

std::vector<AstSymbol> JavaASTScanner::collectSymbols(const std::string& displayPath, const std::string& code){
    std::vector<AstSymbol> out;
    if(code.empty()) return out;

    TSParser* parser = ts_parser_new();
    ts_parser_set_language(parser, tree_sitter_java());
    TSTree* tree = ts_parser_parse_string(parser, nullptr, code.c_str(), (uint32_t)code.size());
    if(!tree){ ts_parser_delete(parser); return out; }

    TSNode root = ts_tree_root_node(tree);
    std::vector<TSNode> stack; stack.push_back(root);

    while(!stack.empty()){
        TSNode n = stack.back(); stack.pop_back();
        const char* t = ts_node_type(n);

        if(std::strcmp(t,"method_invocation")==0){
            std::string seg = node_text(n, code);
            std::string callee = callee_from_segment(seg);
            auto ar = first_arg_literal_from_segment(seg);
            TSPoint p = ts_node_start_point(n);
            size_t line = (size_t)p.row + 1;
            AstSymbol s;
            s.filePath = displayPath;
            s.line = line;
            s.lang = "java";
            s.callee_full = callee;
            s.callee_base = callee;
            s.first_arg = ar.first ? ar.second : std::string();
            out.push_back(std::move(s));
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
