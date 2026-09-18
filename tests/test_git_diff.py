import subprocess

from unsafe_c_finder.git_diff import parse_unified_diff, staged_diff


def test_parse_c_hunk_separates_added_removed_and_context() -> None:
    diff = """\
diff --git old.c old.c
index 1111111..2222222 100644
--- old.c
+++ old.c
@@ -1,4 +1,4 @@
 void copy(char *dst, const char *src)
 {
-    memcpy(dst, src, 8);
+    strcpy(dst, src);
 }
"""

    snippets = parse_unified_diff(diff)

    assert len(snippets) == 1
    assert snippets[0].path == "old.c"
    assert snippets[0].before == "    memcpy(dst, src, 8);"
    assert snippets[0].after == "    strcpy(dst, src);"
    assert "void copy" in snippets[0].context
    assert snippets[0].change_kind == "hunk"


def test_skip_non_c_deleted_and_no_added_hunks() -> None:
    diff = """\
diff --git README.md README.md
--- README.md
+++ README.md
@@ -1 +1 @@
-old
+new
diff --git gone.c gone.c
--- gone.c
+++ /dev/null
@@ -1 +0,0 @@
-int old(void);
diff --git comments.c comments.c
--- comments.c
+++ comments.c
@@ -1 +1,0 @@
-int removed(void);
"""

    assert parse_unified_diff(diff) == []


def test_parse_multiple_hunks_with_spaces_in_path() -> None:
    diff = """\
diff --git source file.c source file.c
--- source file.c
+++ source file.c
@@ -1 +1 @@
-int a = 0;
+int a = 1;
@@ -10 +10 @@
-int b = 0;
+int b = 1;
"""

    snippets = parse_unified_diff(diff)

    assert [snippet.identifier for snippet in snippets] == [
        "source file.c:1",
        "source file.c:2",
    ]


def test_staged_diff_ignores_unstaged_worktree_changes(tmp_path) -> None:
    def git(*args: str) -> None:
        subprocess.run(
            ["git", *args],
            cwd=tmp_path,
            check=True,
            text=True,
            capture_output=True,
        )

    git("init", "-q")
    git("config", "user.name", "Test User")
    git("config", "user.email", "test@example.com")
    source = tmp_path / "sample.c"
    source.write_text("int value(void) { return 0; }\n", encoding="utf-8")
    git("add", "sample.c")
    git("commit", "-qm", "base")

    source.write_text("int value(void) { return 1; }\n", encoding="utf-8")
    git("add", "sample.c")
    source.write_text("int value(void) { return 2; }\n", encoding="utf-8")

    snippets = parse_unified_diff(staged_diff(cwd=tmp_path))

    assert len(snippets) == 1
    assert "return 1" in snippets[0].after
    assert "return 2" not in snippets[0].after
