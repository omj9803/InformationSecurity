1. 
3EPROTO CONNECT
Credential: User1

2.
3EPROTO CONNECT
Credential: User2

3.
3EPROTO KEYXCHG
Algo: Diffie
From: User1
To: User2

-> body 없이 입력해도 보낼 때 난수 생성 후 body로 보냄. 
User1에서 계산 후 바로 User2에게 B값을 보내게 됨. 
각자 계산 후 키 생성한 형태.

4.
3EPROTO KEYXCHG
Algo: AES-256-CBC
From: User1
To: User2

f8uA/XqfIIpdnED+yFj0+w==

-> AES-256-CBC를 위한 IV 벡터 교환

5.
3EPROTO MSGSEND
From: User1
To: User2
Nonce: A/Xqf

Hello