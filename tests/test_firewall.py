"""winplat.firewall 纯函数层测试（M7）：脚本构造与输出解析可离线单测。"""

from winplat import firewall as fw


class TestBuildGetStatusScript:
    def test_script_uses_direct_property_access(self):
        """C2：不得出现 `($r | Get-NetFirewallRule).Enabled` 管道语法
        （PS 5.1 AmbiguousParameterSet 且 exit 0 → 恒 False）。"""
        script = fw._build_get_status_script("'CG-Global'")
        assert "$r.Enabled" in script
        assert "($r | Get-NetFirewallRule)" not in script

    def test_script_handles_missing_rule(self):
        script = fw._build_get_status_script("'CG-Global'")
        assert "if ($r)" in script
        assert "MISSING" in script

    def test_script_embeds_quoted_name(self):
        script = fw._build_get_status_script(fw._ps_quote("O'Brien Rule"))
        assert "'O''Brien Rule'" in script


class TestParseGetStatusOutput:
    def test_true_is_enabled(self):
        assert fw._parse_get_status_output("True") == fw.STATUS_ENABLED

    def test_false_is_disabled(self):
        assert fw._parse_get_status_output("False") == fw.STATUS_DISABLED

    def test_missing_marker(self):
        assert fw._parse_get_status_output("MISSING") == fw.STATUS_MISSING

    def test_empty_output_is_missing_not_enabled(self):
        """cmdlet exit 0 但无输出（如管道语法报错进 stderr）→ 不得猜 Enabled。"""
        assert fw._parse_get_status_output("") == fw.STATUS_MISSING

    def test_garbage_is_missing(self):
        assert fw._parse_get_status_output("无法解析参数集 AmbiguousParameterSet") == fw.STATUS_MISSING
        assert fw._parse_get_status_output("\x00\xff\xfe") == fw.STATUS_MISSING

    def test_none_is_missing(self):
        assert fw._parse_get_status_output(None) == fw.STATUS_MISSING

    def test_whitespace_tolerant(self):
        assert fw._parse_get_status_output("  True\r\n") == fw.STATUS_ENABLED

    def test_bool_semantics(self):
        """三态的 bool() = 是否 Enabled（guardian 兼容旧 bool 消费方）。"""
        assert bool(fw.STATUS_ENABLED) is True
        assert bool(fw.STATUS_DISABLED) is False
        assert bool(fw.STATUS_MISSING) is False


class TestTimeoutClassification:
    def test_timeout_is_not_permission_error(self):
        """L3：PS 超时不得归为 FirewallPermissionError（冷启动≠缺管理员）。"""
        assert issubclass(fw.FirewallTimeoutError, fw.FirewallError)
        assert not issubclass(fw.FirewallTimeoutError, fw.FirewallPermissionError)

    def test_run_ps_timeout_raises_timeout_error(self, monkeypatch):
        import subprocess

        def fake_run(*a, **kw):
            raise subprocess.TimeoutExpired(cmd="powershell", timeout=10)

        monkeypatch.setattr(fw.subprocess, "run", fake_run)
        try:
            fw._run_ps("Write-Output hi")
        except fw.FirewallPermissionError:
            raise AssertionError("timeout must not raise FirewallPermissionError")
        except fw.FirewallTimeoutError:
            pass  # expected
        else:
            raise AssertionError("timeout must raise FirewallTimeoutError")


class TestCreateRuleNoProtocolRestriction:
    def test_v4_script_has_no_tcp_protocol(self):
        """C4：不得 -Protocol TCP（Any 协议才封得住 UDP/QUIC）。"""
        cfg = type("C", (), {
            "rule_name_v4": "T",
            "blocked_cidrs_v4": ["160.79.104.0/23"],
            "rule_name_v6": "T6",
            "blocked_cidrs_v6": ["2606:4700::/32"],
        })()
        captured = []
        monkey_target = fw._run_ps
        def fake_run(script):
            captured.append(script)
        fw._run_ps = fake_run
        try:
            fw.create_rule(cfg)
            fw.create_rule_v6(cfg)
        finally:
            fw._run_ps = monkey_target
        assert all("-Protocol" not in s for s in captured), captured


class TestEnsureExistsSemantics:
    def test_missing_rebuilds(self, monkeypatch):
        calls = []
        monkeypatch.setattr(fw, "_run_ps", lambda s: calls.append(s) or "REBUILD")
        monkeypatch.setattr(fw, "create_rule", lambda cfg: calls.append("create"))
        fw.ensure_exists(type("C", (), {"rule_name_v4": "T"})())
        assert "create" in calls

    def test_present_noop(self, monkeypatch):
        calls = []
        monkeypatch.setattr(fw, "_run_ps", lambda s: calls.append(s) or "OK")
        monkeypatch.setattr(fw, "create_rule", lambda cfg: calls.append("create"))
        fw.ensure_exists(type("C", (), {"rule_name_v4": "T"})())
        assert "create" not in calls


class TestEnableVerifies:
    def test_enable_raises_when_rule_missing(self, monkeypatch):
        """C3：对不存在规则 enable 时 cmdlet exit 0 是假成功，必须抛错。"""
        monkeypatch.setattr(fw, "_run_ps", lambda s: "")
        monkeypatch.setattr(fw, "get_status", lambda cfg: fw.STATUS_MISSING)
        try:
            fw.enable(type("C", (), {"rule_name_v4": "T"})())
        except fw.FirewallError:
            pass
        else:
            raise AssertionError("enable on missing rule must raise")

    def test_enable_ok_when_verified(self, monkeypatch):
        monkeypatch.setattr(fw, "_run_ps", lambda s: "")
        monkeypatch.setattr(fw, "get_status", lambda cfg: fw.STATUS_ENABLED)
        fw.enable(type("C", (), {"rule_name_v4": "T"})())
