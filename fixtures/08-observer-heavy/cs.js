
const obs = new MutationObserver((muts) => {
  for (const m of muts) console.log(m.type);
});
obs.observe(document.documentElement, {childList: true, subtree: true, attributes: true});
setInterval(() => document.querySelectorAll('div'), 100);
document.querySelectorAll('a');
document.querySelectorAll('p');
document.querySelectorAll('span');
document.querySelectorAll('li');
document.querySelectorAll('ul');
document.querySelectorAll('table');
document.querySelectorAll('img');
document.querySelectorAll('input');
document.querySelectorAll('form');
document.querySelectorAll('section');
document.querySelectorAll('header');
document.querySelectorAll('footer');
