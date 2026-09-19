// 轻量自动刷新：每 N 秒重取当前页、只替换 .content，不整页刷新（不闪、不丢滚动）。
// 仅当 <body class="auto-refresh"> 时启用；登录/错误/GC 执行结果页不加该 class。
(function () {
  var body = document.body;
  if (!body.classList.contains("auto-refresh")) return;

  var intervalSec = parseInt(body.dataset.refresh || "5", 10);
  var ind = document.getElementById("refresh-ind");

  function stamp() {
    if (!ind) return;
    var d = new Date();
    var p = function (n) { return String(n).padStart(2, "0"); };
    ind.textContent = "更新于 " + p(d.getHours()) + ":" + p(d.getMinutes()) + ":" + p(d.getSeconds());
  }

  async function tick() {
    if (document.hidden) return; // 后台标签页不刷，省资源
    try {
      var resp = await fetch(location.pathname + location.search, {
        headers: { "X-Requested-With": "refresh" },
      });
      if (resp.status !== 200) { location.reload(); return; } // 会话过期等交给整页跳转
      var html = await resp.text();
      var doc = new DOMParser().parseFromString(html, "text/html");
      var next = doc.querySelector(".content");
      var cur = document.querySelector(".content");
      if (next && cur) {
        cur.innerHTML = next.innerHTML;
        stamp();
      }
    } catch (e) {
      // 网络抖动忽略，下个周期再试
    }
  }

  stamp();
  setInterval(tick, intervalSec * 1000);
})();
