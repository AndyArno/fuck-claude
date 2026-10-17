"""winplat.firewall 纯函数层测试（M7）：脚本构造与输出解析可离线单测。"""

from winplat import firewall as fw

import pytest


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


class TestFakeipRuleScripts:
    """CG-FakeIP：脚本构造（离线）——Any 协议 + 规则名 + 远端地址集。"""

    def _cfg(self):
        return type("C", (), {"rule_name_fakeip": "CG-FakeIP"})()

    def test_create_script_no_protocol(self, monkeypatch):
        captured = []
        monkeypatch.setattr(fw, "_run_ps", lambda s: captured.append(s))
        fw.create_rule_fakeip(self._cfg(), ["198.18.0.1", "198.18.0.2"])
        s = captured[0]
        assert "-Protocol" not in s
        assert "New-NetFirewallRule" in s
        assert "Outbound" in s
        assert "198.18.0.1" in s and "198.18.0.2" in s

    def test_create_uses_ps_array(self, monkeypatch):
        captured = []
        monkeypatch.setattr(fw, "_run_ps", lambda s: captured.append(s))
        fw.create_rule_fakeip(self._cfg(), ["198.18.0.1"])
        assert "@('198.18.0.1')" in captured[0]

    def test_enable_verifies_status(self, monkeypatch):
        monkeypatch.setattr(fw, "_run_ps", lambda s: "")
        monkeypatch.setattr(fw, "get_status_fakeip",
                            lambda cfg: fw.STATUS_MISSING)
        try:
            fw.enable_fakeip(self._cfg())
        except fw.FirewallError:
            pass
        else:
            raise AssertionError("enable on missing fakeip rule must raise")

    def test_get_status_uses_rule_name(self, monkeypatch):
        captured = []
        monkeypatch.setattr(fw, "_run_ps", lambda s: captured.append(s) or "True")
        assert fw.get_status_fakeip(self._cfg()) == fw.STATUS_ENABLED
        assert "'CG-FakeIP'" in captured[0]

    def test_ensure_exists_rebuilds_only_when_missing(self, monkeypatch):
        calls = []
        monkeypatch.setattr(fw, "_run_ps",
                            lambda s: calls.append(s) or "REBUILD")
        monkeypatch.setattr(fw, "create_rule_fakeip",
                            lambda c, ips: calls.append(("create", ips)))
        fw.ensure_exists_fakeip(self._cfg(), ["198.18.0.1"])
        assert ("create", ["198.18.0.1"]) in calls
        calls.clear()
        monkeypatch.setattr(fw, "_run_ps", lambda s: calls.append(s) or "OK")
        fw.ensure_exists_fakeip(self._cfg(), ["198.18.0.1"])
        assert not any(c == ("create", ["198.18.0.1"]) for c in calls)


class TestSetBlockingOffline:
    """P1-3：set_blocking 离线断言（喂 PS 输出文本，不发真 PS）。

    动词去掉 -ErrorAction Stop 后，CG-FakeIP 缺失场景必须由复查层
    正确判读——这组用例锁住按方向收紧的复查语义。
    复查输出为逐名"名字=Enabled"标记（P1-3 复审：数组 Get 顺序不可
    依赖，按行序对应规则名是 fail-closed 破口）。"""

    def _cfg(self):
        return type("C", (), {
            "rule_name_v4": "CG-Global",
            "rule_name_fakeip": "CG-FakeIP",
        })()

    def _run(self, monkeypatch, out):
        captured = []
        # 强制走 PS 全量路径：本类断言的是 PS 复查语义；不 stub 时快车道
        # 会碰真实防火墙（本机有同名规则时 netsh rc=0），非密闭。
        monkeypatch.setattr(fw, "_netsh_set_enabled", lambda n, e: False)
        monkeypatch.setattr(fw, "_run_ps",
                            lambda s: captured.append(s) or out)
        return captured

    def test_script_shape(self, monkeypatch):
        """动词不带 -ErrorAction Stop（P1-3 核心）；数组字面量；无 -Protocol；
        复查逐名标记（不依赖返回顺序）。"""
        captured = self._run(monkeypatch, "CG-Global=True\nCG-FakeIP=True\n")
        fw.set_blocking(self._cfg(), True)
        s = captured[0]
        verb_part = [ln for ln in s.split(";") if "NetFirewallRule" in ln
                     and "Get-" not in ln][0]
        assert "-ErrorAction Stop" not in verb_part
        assert "@('CG-Global','CG-FakeIP')" in s
        assert "-Protocol" not in s
        assert "foreach ($n in" in s  # 逐名复查，非数组 Get 按序对应

    def test_disable_fakeip_missing_idempotent(self, monkeypatch):
        """CG-FakeIP 不存在（仅 CG-Global=False）→ 幂等放行，不抛。"""
        self._run(monkeypatch, "CG-Global=False\n")
        fw.set_blocking(self._cfg(), False)  # 不得抛

    def test_disable_both_missing_idempotent(self, monkeypatch):
        """两条都不存在（空输出）→ 幂等放行。"""
        self._run(monkeypatch, "")
        fw.set_blocking(self._cfg(), False)  # 不得抛

    def test_enable_fakeip_missing_ok(self, monkeypatch):
        """enable 后仅 CG-Global 在（CG-Global=True）→ 达标不抛。"""
        self._run(monkeypatch, "CG-Global=True\n")
        fw.set_blocking(self._cfg(), True)  # 不得抛

    def test_enable_global_missing_raises(self, monkeypatch):
        """enable 后空输出（CG-Global 缺失）→ 抛 FirewallError。"""
        self._run(monkeypatch, "")
        try:
            fw.set_blocking(self._cfg(), True)
        except fw.FirewallError:
            pass
        else:
            raise AssertionError("enable with no rules must raise")

    def test_enable_only_fakeip_present_raises(self, monkeypatch):
        """fail-closed 回归（P1-3 复审）：CG-Global 缺失而 CG-FakeIP 存在
        且 Enabled 时，不得把 FakeIP 的 True 误认作 CG-Global 已启用。"""
        self._run(monkeypatch, "CG-FakeIP=True\n")
        try:
            fw.set_blocking(self._cfg(), True)
        except fw.FirewallError:
            pass
        else:
            raise AssertionError(
                "CG-FakeIP-only must not satisfy CG-Global check")

    def test_enable_partial_failure_raises(self, monkeypatch):
        """enable 后 CG-Global 仍 Disabled（CG-Global=False）→ 必抛。"""
        self._run(monkeypatch, "CG-Global=False\nCG-FakeIP=True\n")
        try:
            fw.set_blocking(self._cfg(), True)
        except fw.FirewallError:
            pass
        else:
            raise AssertionError("partial enable must raise")

    def test_disable_partial_failure_raises(self, monkeypatch):
        """disable 后仍有 Enabled（CG-Global=True）→ 抛错（复查强度不变）。"""
        self._run(monkeypatch, "CG-Global=True\nCG-FakeIP=False\n")
        try:
            fw.set_blocking(self._cfg(), False)
        except fw.FirewallError:
            pass
        else:
            raise AssertionError("partial disable must raise")


class TestNetshFastLane:
    """netsh 快车道：规则存在时绕过 PS（~0.5s vs 2.7-3.8s）；
    任一失败回退 PS 全量路径。离线——monkeypatch 两个底层入口。"""

    def _cfg(self):
        return type("C", (), {
            "rule_name_v4": "CG-Global",
            "rule_name_fakeip": "CG-FakeIP",
            "blocked_cidrs_v4": ["160.79.104.0/23"],
        })()

    def _netsh(self, monkeypatch, results):
        """results: {display_name: bool}；返回调用记录。"""
        calls = []

        def fake(name, enabled):
            calls.append((name, enabled))
            return results.get(name, False)

        monkeypatch.setattr(fw, "_netsh_set_enabled", fake)
        return calls

    def _ps_must_not_run(self, monkeypatch):
        monkeypatch.setattr(
            fw, "_run_ps",
            lambda s: (_ for _ in ()).throw(
                AssertionError("fast lane must not invoke PS")))

    # ---- set_blocking ----

    def test_set_blocking_fast_lane_skips_ps(self, monkeypatch):
        calls = self._netsh(monkeypatch,
                            {"CG-Global": True, "CG-FakeIP": True})
        self._ps_must_not_run(monkeypatch)
        fw.set_blocking(self._cfg(), True)
        assert calls == [("CG-Global", True), ("CG-FakeIP", True)]

    def test_set_blocking_disable_fast_lane(self, monkeypatch):
        calls = self._netsh(monkeypatch,
                            {"CG-Global": True, "CG-FakeIP": True})
        self._ps_must_not_run(monkeypatch)
        fw.set_blocking(self._cfg(), False)
        assert calls == [("CG-Global", False), ("CG-FakeIP", False)]

    def test_set_blocking_fakeip_missing_tolerated(self, monkeypatch):
        """CG-Global 成功（=权限正常）后 CG-FakeIP rc=1 只可能是缺失：
        两个方向都可接受，不回退 PS。"""
        self._netsh(monkeypatch, {"CG-Global": True, "CG-FakeIP": False})
        self._ps_must_not_run(monkeypatch)
        fw.set_blocking(self._cfg(), True)   # 不得抛、不得调 PS
        fw.set_blocking(self._cfg(), False)

    def test_set_blocking_global_fail_falls_back_to_ps(self, monkeypatch):
        """CG-Global netsh 失败（缺失/权限）→ 回退 PS 全量路径。"""
        self._netsh(monkeypatch, {"CG-Global": False})
        captured = []
        monkeypatch.setattr(
            fw, "_run_ps",
            lambda s: captured.append(s) or "CG-Global=True\nCG-FakeIP=True\n")
        fw.set_blocking(self._cfg(), True)
        assert captured and "Enable-NetFirewallRule" in captured[0]

    # ---- block_all ----

    def test_block_all_fast_lane_skips_ps(self, monkeypatch):
        calls = self._netsh(monkeypatch,
                            {"CG-Global": True, "CG-FakeIP": True})
        self._ps_must_not_run(monkeypatch)
        fw.block_all(self._cfg(), ["198.18.0.1"])
        assert ("CG-FakeIP", True) in calls

    def test_block_all_empty_fakeips_skips_fakeip_netsh(self, monkeypatch):
        """fakeip_ips 为空：CG-FakeIP 本就可能不存在，netsh 都不发。"""
        calls = self._netsh(monkeypatch, {"CG-Global": True})
        self._ps_must_not_run(monkeypatch)
        fw.block_all(self._cfg(), None)
        assert calls == [("CG-Global", True)]

    def test_block_all_known_fakeips_missing_falls_back(self, monkeypatch):
        """fakeip 集合已知但规则缺失 → 回退 PS 重建（保原 block_all 语义）。"""
        self._netsh(monkeypatch, {"CG-Global": True, "CG-FakeIP": False})
        captured = []
        monkeypatch.setattr(fw, "_run_ps",
                            lambda s: captured.append(s) or "True\nTrue\n")
        fw.block_all(self._cfg(), ["198.18.0.1"])
        assert captured and "New-NetFirewallRule" in captured[0]

    def test_block_all_global_fail_falls_back(self, monkeypatch):
        self._netsh(monkeypatch, {"CG-Global": False})
        captured = []
        monkeypatch.setattr(fw, "_run_ps",
                            lambda s: captured.append(s) or "True\n")
        fw.block_all(self._cfg(), None)
        assert captured


class TestEnsureEnabledV6Offline:
    """P1-4：CG-V6 永久 Enabled 硬约束的执行体——MISSING→重建、
    DISABLED→强制 Enabled、ENABLED→noop 三分支此前零脚本级断言。"""

    def _cfg(self):
        return type("C", (), {
            "rule_name_v4": "CG-Global",
            "rule_name_v6": "CG-V6",
            "blocked_cidrs_v6": ["2607:6bc0::/48"],
        })()

    def test_missing_recreates(self, monkeypatch):
        calls = []

        def fake_run_ps(script):
            calls.append(script)
            if "Get-NetFirewallRule" in script:
                return "MISSING"     # 查询 → 缺失
            return "OK"              # 重建/enable → 成功

        monkeypatch.setattr(fw, "_run_ps", fake_run_ps)
        monkeypatch.setattr(fw, "create_rule_v6",
                            lambda cfg: calls.append("create_rule_v6"))
        fw.ensure_enabled_v6(self._cfg())
        assert "create_rule_v6" in calls

    def test_disabled_enables(self, monkeypatch):
        calls = []

        def fake_run_ps(script):
            calls.append(script)
            if "Get-NetFirewallRule" in script:
                return "DISABLED"    # 查询 → 被禁用
            return "OK"

        monkeypatch.setattr(fw, "_run_ps", fake_run_ps)
        fw.ensure_enabled_v6(self._cfg())
        assert any("Enable-NetFirewallRule" in s and "CG-V6" in s
                   for s in calls)

    def test_enabled_noop(self, monkeypatch):
        calls = []

        def fake_run_ps(script):
            calls.append(script)
            return "OK"              # 查询输出 OK = 已 Enabled

        monkeypatch.setattr(fw, "_run_ps", fake_run_ps)
        monkeypatch.setattr(fw, "create_rule_v6",
                            lambda cfg: calls.append("create_rule_v6"))
        fw.ensure_enabled_v6(self._cfg())
        assert "create_rule_v6" not in calls
        assert not any("Enable-NetFirewallRule" in s for s in calls)


class TestRunPsErrorClassification:
    """P2-14（B 侧）：_run_ps rc≠0 分类与 _dec UTF-8→mbcs 回退。
    全部 monkeypatch subprocess.run，零真实子进程。"""

    def _cfg_module_run(self, monkeypatch, returncode, stdout=b"", stderr=b""):
        import types

        def fake_run(cmd, capture_output, timeout, creationflags):
            return types.SimpleNamespace(
                returncode=returncode, stdout=stdout, stderr=stderr)

        captured = {}
        real_run = fw.subprocess.run

        def spy(cmd, **kw):
            captured["cmd"] = cmd
            captured["kw"] = kw
            return fake_run(cmd, **kw)

        monkeypatch.setattr(fw.subprocess, "run", spy)
        return captured

    def test_access_denied_chinese_raises_permission(self, monkeypatch):
        self._cfg_module_run(monkeypatch, 1, stderr="拒绝访问。".encode("gbk"))
        with pytest.raises(fw.FirewallPermissionError):
            fw._run_ps("Get-NetFirewallRule")

    def test_access_denied_english_raises_permission(self, monkeypatch):
        self._cfg_module_run(monkeypatch, 1,
                             stderr=b"Access is denied.")
        with pytest.raises(fw.FirewallPermissionError):
            fw._run_ps("Get-NetFirewallRule")

    def test_access_denied_permissiondenied_marker(self, monkeypatch):
        self._cfg_module_run(monkeypatch, 1,
                             stderr=b"PermissionDenied: cmdlet")
        with pytest.raises(fw.FirewallPermissionError):
            fw._run_ps("Get-NetFirewallRule")

    def test_generic_error_raises_firewall_error(self, monkeypatch):
        self._cfg_module_run(monkeypatch, 1, stderr=b"some random failure")
        with pytest.raises(fw.FirewallError) as ei:
            fw._run_ps("Get-NetFirewallRule")
        assert not isinstance(ei.value, fw.FirewallPermissionError)
        assert "some random failure" in str(ei.value)

    def test_ps_flags_no_profile_noninteractive_no_window(self, monkeypatch):
        captured = self._cfg_module_run(monkeypatch, 0, stdout=b"ok\n")
        assert fw._run_ps("Write-Output ok") == "ok"
        cmd, kw = captured["cmd"], captured["kw"]
        assert "-NoProfile" in cmd and "-NonInteractive" in cmd
        assert kw.get("creationflags") == fw.subprocess.CREATE_NO_WINDOW

    def test_dec_utf8_then_mbcs_fallback(self, monkeypatch):
        """UTF-8 可解码原样输出；非法 UTF-8 回退 mbcs（GBK）。"""
        self._cfg_module_run(monkeypatch, 0, stdout=b"ok\n")
        assert fw._run_ps("'ok'") == "ok"
        # GBK 编码的中文（非法 UTF-8 序列）→ mbcs 兜底正确还原
        self._cfg_module_run(
            monkeypatch, 0, stdout="拒绝访问".encode("gbk"))
        assert "拒绝访问" in fw._run_ps("'拒绝访问'")


class TestBlockAllPsScriptShape:
    """P2-9：PS 回退路径——CG-FakeIP 存在即无条件 Enable（n2 Enable 段
    恒在），缺失且 fakeip_ips 非空才含 New-NetFirewallRule 重建段。"""

    def _cfg(self):
        return type("C", (), {
            "rule_name_v4": "CG-Global",
            "rule_name_fakeip": "CG-FakeIP",
            "blocked_cidrs_v4": ["160.79.104.0/23"],
        })()

    def test_empty_fakeips_still_enables_n2(self, monkeypatch):
        captured = []
        monkeypatch.setattr(fw, "_netsh_set_enabled", lambda n, e: False)
        monkeypatch.setattr(fw, "_run_ps",
                            lambda s: captured.append(s) or "True\n")
        fw.block_all(self._cfg(), None)
        assert "Enable-NetFirewallRule -DisplayName 'CG-FakeIP'" in captured[0]
        # 无重建段
        assert "New-NetFirewallRule -DisplayName 'CG-FakeIP'" not in captured[0]

    def test_nonempty_fakeips_contains_rebuild_segment(self, monkeypatch):
        captured = []
        monkeypatch.setattr(fw, "_netsh_set_enabled", lambda n, e: False)
        monkeypatch.setattr(fw, "_run_ps",
                            lambda s: captured.append(s) or "True\nTrue\n")
        fw.block_all(self._cfg(), ["198.18.0.1", "198.18.0.2"])
        script = captured[0]
        assert "New-NetFirewallRule -DisplayName 'CG-FakeIP'" in script
        assert "Enable-NetFirewallRule -DisplayName 'CG-FakeIP'" in script
        assert "@('198.18.0.1','198.18.0.2')" in script

    def test_script_never_writes_protocol(self, monkeypatch):
        captured = []
        monkeypatch.setattr(fw, "_netsh_set_enabled", lambda n, e: False)
        monkeypatch.setattr(fw, "_run_ps",
                            lambda s: captured.append(s) or "True\nTrue\n")
        fw.block_all(self._cfg(), ["198.18.0.1"])
        assert "-Protocol" not in captured[0]
