DELETE_KOKEN="github创建的token"
GithubName="github名"

for repName in $(cat repos.txt)
do
    echo "Delete "$repName
    curl -XDELETE -H "Authorization: token ${DELETE_KOKEN}" https://api.github.com/repos/${GithubName}/${repName}
done
