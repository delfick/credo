document.body.style.backgroundSize = "contain";

chrome.extension.sendMessage({}, function(response) {
	var readyStateCheckInterval = setInterval(function() {

	if (document.readyState === "complete") {
		clearInterval(readyStateCheckInterval);

    var obj = JSON.parse(document.getElementsByTagName("pre")[0].innerHTML);
    var done = [];
    for (var i = 0; i < obj["Cookies"].length; i++) {
      chrome.runtime.sendMessage({"cookie": obj["Cookies"][i]}, function() { done.push(i) });
    }

    var interval = setInterval(function() {
      if (done.length >= obj["Cookies"].length) {
        window.location = obj["Location"]
        clearInterval(interval);
      }
    }, 10)
	}
	}, 10);
});
