import yara

# 创建测试规则
rule_src = """
rule test {
    strings:
        $a = "malware"
        $b = "virus"
    condition:
        any of them
}
"""

compiled = yara.compile(source=rule_src)
matches = compiled.match(data=b"this is malware test virus data")

print("=== 检查 match.strings 结构 ===")
for match in matches:
    print(f"\n规则: {match.rule}")
    print(f"strings类型: {type(match.strings)}")
    print(f"strings: {match.strings}")
    
    for s in match.strings:
        print(f"\n  字符串对象类型: {type(s)}")
        print(f"  字符串对象: {s}")
        print(f"  可用属性: {dir(s)}")
        
        # 正确的访问方法
        print(f"  identifier: {s.identifier}")
        print(f"  instances: {s.instances}")
        print(f"  instances类型: {type(s.instances)}")
        print(f"  instances长度: {len(s.instances)}")
