[Fact]
public void Test_XSS_Prevention_Logic() {
    // 模拟输入包含恶意脚本
    string maliciousInput = "<script>alert('xss')</script>";
    var encoder = HtmlEncoder.Default;
    // 验证输出是否被转义
    var result = encoder.Encode(maliciousInput);
    Assert.DoesNotContain("<script>", result);
}