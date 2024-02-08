// run on https://archive.synology.com/download/ToolChain/Synology%20NAS%20GPL%20Source/7.2-64570

function get_detail(tr) {
  const [platform, md5] = Array.from(tr.querySelectorAll('td')).map(td => td.innerText.trim()).filter(t => t !== '');
  const a = tr.querySelector('a');
  const name = a.innerText.trim();
  const tar_url = a.href.trim();

  const base = 'v' + name.replace('linux-', '').replace('.x-bsp.txz', '').replace('.x.txz', '');

  return {
    base,
    platform,
    name,
    tar_url,
    md5
  }
}

const details = Array.from(document.querySelectorAll('tr')).filter(tr => {
  const a = tr.querySelector('a');
  if (a) {
    const name = a.innerText.trim();
    return name !== 'linux-firmware.txz' && name !== 'linux-pam.txz' && name.startsWith('linux-');
  } else {
    return false
  }
}).map(get_detail);
console.log(JSON.stringify(details));