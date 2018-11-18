keys_array=(5JTYRqTA1V1ie8C4uNQNu2UsLyKiX9qxijNPwSREVx2FetCaskd
EOS8L5DdEgdU1Y4UAKLyH6AexswwHWzsMj8SRwcpwdqrvjKtcmP2d
5KMAQS76KSukcLPHfqAnLV1EjRmX1UCAmeLQtk4bTZG3WoDjeU7
EOS5YSeCqxoQJPyyndwnSvopJuXgX1SyzveHAWKNpRPGZTfj86jpC
5HvfaTkBnVsTr9xgjZ96S9TJzsZv8sqKiCX9hA8xDncE7BK83d4
EOS7tHFyTYh7mtwwvGmzA9aLZgz4NDL2ASA54bVzGJKpRDiVNDsDh
5K5x7HnWweb7SaUQ2TF7HZaafsyV68qidrLvhpnN9DCu272JMAZ
EOS8QcrTjW4PQHsNLtTPLB6V3jMKVvfTMHwTKpLDwbLBs6mxDMVxD
5JcApVPXA8qgCJMeiMtecEjrQFsmtca3Jqcj2C6E4f3zjW3Z1HC
EOS7e9qQufn2Dnf2oNLM9Qozf99WwQTLdYamvUPzTAyu2a9Lc4bHa
5K8HV3SfewaVdo1Uua4DfCAnX49TRWseo6nMWBcsxiwXY5ySAP1
EOS8G5127mbtWgoYb2bm8jjwQB1EDdXCX2a6wh73pk5NkT22QN4cG
5JrWMmBj4FzgUpvZ4wnyAWMFRuRPr9K8K2KeBvPpBFfJnJ7mVzR
EOS825uncuQFfgbZND4jh3zoiqnzrXXYzhDT35Z5kWthf4u8TeECX
5JKymuAVY8MFJ8wish5ioM3adR1V9LncAaGP1QzUnQpMDUx8yuY
EOS7ka9TPDSvecLDV3HpUTv3MA9boRYPvNA5PBuR6CvVJAEoT8Gng
5KS3XNjyjim8g8erzrNe9LoHwHoA4CijZmwSaBCZgN1WRRHCgo7
EOS8AiSDLJjDJ8QVg2DDX2XCkMfWTWQ1J9QWAxcE3PY25B9LVem4Z
5JycB4oFx71ZLGN3aV1HJDMJRQPUJfvUp6DgmECzQ7GTZYFtfmT
EOS7iBL5W6nPT98j6QnZaaRovnTHZrduEd52VTemm6i1vzEaWSDyh
5JQJJAoETfgLZ9ZEqUgf7NTA6m8wb6TSUvAhqM8nY15dNBkRqQi
EOS6Dn49pFgLreQvVza6iAAhJ1vM7iKazJAvCnds9CSShjNzcGc4w
5KDVVejCJqb3whgERGTYA41yg8gyzmEWd9tVDtWsnDiR6mPUZVJ
EOS598UoQHhNcnZMBqL6wK8MQ5KyFTmTDhxvaK5mqr7MWWFcmADLG
5K4LhLvodnoeVP6BHEtjvLgi2pwmDG6VWqesrcgTZMJw5obbnCu
EOS8Ya5rKdeowu9Ee8SmXLc5qTsgMN6gXDb38bKoRMfBZT4K5ak7H
5KaQfLLRA365bhFwo4VyHYMxQ8SUiWtKLiKQog94bqb8Fp9F2qo
EOS6TVpQXAKjjB8gAjNjGsK58Fomq6b5jXRPxTmgAv4MzfwKz9WZo
5JRXYdAcRoeuEYdKPxnBQAcgZAoGZdrgGoGy4Sk3vJsYS8vGDGt
EOS8Wm8WL9UG1ZgYWFEZByvRP7hVUGBcpTc4rgVFuRmWyfBLXyq3j
5JEFRZGKhV92HfMze6tm1syH8k3ykJrAq5iXWVdoFKvjsENpi4q
EOS4vbjAytcQBShjNkgQLV9U2GUZm6Q9DtErzW8L3gfC4Fx7uSFs8
5JdnHU7UCSB5ewfinr1ZRxkFsU4oAuMbzCcnEDh1KuNuY5ZzsFo
EOS6GaCU45AYNwpFuaugZgMVNwvYgpT2Nq2eAV5BKJBBocaVhydCu
5KPEuWFZR3QykdQ7ZzPA4Koi2E8xibja5FMioxn591k1iUzSjes
EOS7aToveoUYnR1FP8oqwG8GpRdfsvcPAeiPZRjPscqJEFJTpig4s
5J7UPZKW1oGPtN8TdWuLQMyNVqn1hvVkuLdo6e8AA3UpypQFj8m
EOS6du3Vpe5GfHAcK32WDmH7M4P1Tc8c9dgjT6L8K134QmJmw8UTL
5KRSjctS6hvB8aJXuX3pKUYhWm4m3ik7NAq881AxpakGXvuQwuS
EOS88QiMR1yVSNP566fjvLwjhYzezAWMDDU1iNumYGKpFme76Khre)

getIndexByUsername()
{
    character=`echo $1 | sed 's/user//'`
    decValue=`printf "%d\n" \'$character`
    index=`expr $decValue - 97`
    extIndex=`expr $index \* 4`
    return  $extIndex
}

getOwnerPrivateKey()
{
    getIndexByUsername $1
    echo ${keys_array["$?"]}
}

getOwnerPublicKey()
{
    getIndexByUsername $1
    index=$(expr $? + 1)
    echo ${keys_array["$index"]}

}

getActivePrivateKey()
{
    getIndexByUsername $1
    index=$(expr $? + 2)
    echo ${keys_array["$index"]}
}

getActivePublicKey()
{
    getIndexByUsername $1
    index=$(expr $? + 3)
    echo ${keys_array["$index"]}
}
