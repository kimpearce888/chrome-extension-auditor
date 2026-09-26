
fetch("https://api.example.com/v1/data");
fetch("https://analytics.example.net/collect", {method: "POST"});
const xhr = new XMLHttpRequest();
xhr.open("GET", "https://cdn.example.net/lib.js");
xhr.send();
const ws = new WebSocket("wss://rt.example.org/socket");
navigator.sendBeacon("https://beacon.example.io/t", "ping");
fetch(`https://dyn.example.com/${path}`);
fetch(buildUrl());
const es = new EventSource("https://stream.example.dev/events");
