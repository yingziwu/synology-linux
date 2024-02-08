import os
import json
import subprocess
import shutil
import tempfile
import tarfile
import hashlib
import time
from operator import itemgetter

import httpx

linux_repo_path = '/srv/app/fork/synology-linux/linux/'

branch_name_template = '{platform}-{name}'
commit_message_template = '''Import DSM {dsm_version} {platform} {name}
Base on Linux Kernal {kernal_base}

tar url: {tar_url}
tar md5sum: {md5}
from: https://archive.synology.com/download/ToolChain/Synology%20NAS%20GPL%20Source/{dsm_version}
'''


def is_md5_match(b: bytes, md5: str) -> bool:
    return hashlib.md5(b).hexdigest() == md5


def is_branch_exists(repo_path: str, branch_name: str) -> bool:
    try:
        subprocess.check_output(
            ['git', '-C', repo_path, 'show-ref', '--verify', '--quiet', 'refs/heads/{}'.format(branch_name)])
        return True
    except subprocess.CalledProcessError:
        return False


def git_create_branch(repo_path: str, base: str, branch_name: str):
    if is_branch_exists(repo_path, branch_name):
        print('switch to branch: {}'.format(branch_name))
        subprocess.run(['git', '-C', repo_path, 'switch', branch_name])
    else:
        print('create branch: {}'.format(branch_name))
        subprocess.run(['git', '-C', repo_path, 'checkout', base])
        subprocess.run(['git', '-C', repo_path, 'switch', '-c', branch_name])


def delete_all_files(folder_path: str):
    print('delete all files on {}'.format(folder_path))
    file_list = filter(lambda x: x not in ['.git', '.gitignore', '.get_maintainer.ignore'], os.listdir(folder_path))
    for f in file_list:
        p = os.path.join(folder_path, f)
        if os.path.isdir(p):
            shutil.rmtree(p)
        else:
            os.unlink(p)


def copy_tree(src: str, dst: str):
    print('copy files in {} to {}'.format(src, dst))
    for f in os.listdir(src):
        p = os.path.join(src, f)
        if os.path.isdir(p):
            shutil.copytree(p, os.path.join(dst, f), symlinks=True)
        else:
            shutil.copy2(p, dst)


def git_add_all_and_commit(repo_path: str, commit_message: str):
    print('git add --all && git commit')
    subprocess.run(['git', '-C', repo_path, 'add', '--all'])
    subprocess.run(['git', '-C', repo_path, 'commit', '-m', commit_message])


def download_and_extract(s):
    name, tar_url, md5 = itemgetter('name', 'tar_url', 'md5')(s)

    tmp_folder_path = tempfile.mkdtemp()
    tar_path = os.path.join(tmp_folder_path, name)

    print('downloading {}'.format(tar_url))
    need_download = True
    retry_count = 0
    while need_download and retry_count <= 5:
        try:
            r = httpx.get(
                tar_url,
                headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0'})
            content = r.content
            need_download = False
        except BaseException as e:
            print('Download failed! Retry...')
            print(e)
            retry_count += 1
            time.sleep(2 ** retry_count + 1)

    assert is_md5_match(content, md5)

    with open(tar_path, 'wb') as f:
        f.write(content)

    with tarfile.open(tar_path) as tar:
        tar.extractall(tmp_folder_path)

    extract_folder_name = list(filter(lambda x: not x.endswith('.txz'), os.listdir(tmp_folder_path)))[0]
    extract_foler_path = os.path.join(tmp_folder_path, extract_folder_name)

    s['tmp_folder_path'] = tmp_folder_path
    s['extract_foler_path'] = extract_foler_path
    return s


def do_task(dsm_version: str, s):
    print('start task of DMS {} {} {}'.format(dsm_version, s['platform'], s['name']))
    s = download_and_extract(s)

    branch_name = branch_name_template.format(platform=s['platform'], name=s['name'].replace('.txz', ''))
    commit_message = commit_message_template.format(
        dsm_version=dsm_version, kernal_base=s['base'],
        platform=s['platform'], name=s['name'], tar_url=s['tar_url'], md5=s['md5'])

    git_create_branch(linux_repo_path, s['base'], branch_name)
    delete_all_files(linux_repo_path)
    copy_tree(s['extract_foler_path'], linux_repo_path)
    git_add_all_and_commit(linux_repo_path, commit_message)

    shutil.rmtree(s['tmp_folder_path'])


def main():
    file_path = os.path.realpath(__file__)
    folder_path = os.path.dirname(file_path)

    resources_folder_path = os.path.join(folder_path, 'resources')

    versions = sorted(os.listdir(resources_folder_path))
    for version in versions:
        with open(os.path.join(resources_folder_path, version), 'r') as f:
            sources = json.load(f)
        for s in sources:
            do_task(version.replace('.json', ''), s)


if __name__ == '__main__':
    main()
