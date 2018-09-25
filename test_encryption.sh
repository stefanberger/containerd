#!/usr/bin/env bash

sudo chmod 777 /run/containerd/containerd.sock

CTR=${CTR:-./bin/ctr}
SLEEP_TIME=${SLEEP_TIME:-2.0}

ALPINE=docker.io/library/alpine:latest
ALPINE_ENC=docker.io/library/alpine:enc
ALPINE_DEC=docker.io/library/alpine:dec

# gpg2 --export-secret-key ...
GPGTESTKEY1="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"
GPGTESTKEY2="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"

GPG_DIR_AS_TGZ="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"

trap "cleanup" EXIT QUIT

cleanup() {
	if [ -n "${WORKDIR}" ]; then
		rm -rf ${WORKDIR}
	fi
}
WORKDIR=$(mktemp -d)

failExit() {
	local rc=$1
	local msg="$2"

	if [ $rc -ne 0 ]; then
		echo "Error: $msg" >&2
		echo >&2
		exit 1
	fi
}

$CTR images rm ${ALPINE_ENC} ${ALPINE_DEC} &>/dev/null
$CTR images pull --all-platforms ${ALPINE} &>/dev/null
failExit $? "Image pull failed"

LAYER_INFO="$($CTR images layerinfo ${ALPINE})"
failExit $? "Image layerinfo on plain image failed"

setupPGP() {
	GPGHOMEDIR=${WORKDIR}/gpg2

	if [ -z "$(type -P gpg2)" ]; then
		failExit 1 "Missing gpg2 executable."
	fi

	pushd ${WORKDIR} &>/dev/null
	echo ${GPG_DIR_AS_TGZ} | base64 -d | tar -xz
	popd &>/dev/null
}

testPGP() {
	setupPGP
	echo "Testing PGP type of encryption"
	$CTR images encrypt \
		--gpg-homedir ${GPGHOMEDIR} \
		--gpg-version 2 \
		--recipient testkey1@key.org \
		${ALPINE} ${ALPINE_ENC}
	failExit $? "Image encryption with PGP failed"

	LAYER_INFO_ENC="$($CTR images layerinfo ${ALPINE_ENC})"
	failExit $? "Image layerinfo on PGP encrypted image failed"

	diff <(echo "${LAYER_INFO}"     | gawk '{print $3}') \
	     <(echo "${LAYER_INFO_ENC}" | gawk '{print $3}' )
	failExit $? "Image layerinfo on PGP encrypted image shows differences in architectures"

	diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
	     <(echo -n "ENCRYPTIONpgp" )
	failExit $? "Image layerinfo on PGP encrypted image shows unexpected encryption"

	$CTR images decrypt \
		--gpg-homedir ${GPGHOMEDIR} \
		--gpg-version 2 \
		--key <(echo "${GPGTESTKEY1}" | base64 -d) \
		${ALPINE_ENC} ${ALPINE_DEC}
	failExit $? "Image decryption with PGP failed"

	LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
	failExit $? "Image layerinfo on decrypted image failed (PGP)"

	diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
	failExit $? "Image layerinfos are different (PGP)"

	$CTR images rm ${ALPINE_DEC} &>/dev/null
	sleep ${SLEEP_TIME}

	echo "PASS: PGP Type of encryption"
	echo

	echo "Testing adding a PGP recipient"
	$CTR images encrypt \
		--gpg-homedir ${GPGHOMEDIR} \
		--gpg-version 2 \
		--key <(echo "${GPGTESTKEY1}" | base64 -d) \
		--recipient testkey2@key.org ${ALPINE_ENC}
	failExit $? "Adding recipient to PGP encrypted image failed"
	sleep ${SLEEP_TIME}

	LAYER_INFO_ENC="$($CTR images layerinfo ${ALPINE_ENC})"
	failExit $? "Image layerinfo on PGP encrypted image failed"

	diff <(echo "${LAYER_INFO}"     | gawk '{print $3}') \
	     <(echo "${LAYER_INFO_ENC}" | gawk '{print $3}' )
	failExit $? "Image layerinfo on PGP encrypted image shows differences in architectures"

	diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $6 $7}' | sort | uniq | tr -d '\n') \
	     <(echo -n "0x6d6d5017a3752cbd,0xb0310f009d3abc2fRECIPIENTS" )
	failExit $? "Image layerinfo on PGP encrypted image shows unexpected recipients"

	for privkey in ${GPGTESTKEY1} ${GPGTESTKEY2}; do
		$CTR images decrypt \
			--gpg-homedir ${GPGHOMEDIR} \
			--gpg-version 2 \
			--key <(echo "${privkey}" | base64 -d) \
			${ALPINE_ENC} ${ALPINE_DEC}
		failExit $? "Image decryption with PGP failed"
		sleep ${SLEEP_TIME}

		LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
		failExit $? "Image layerinfo on decrypted image failed (PGP)"

		diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
		failExit $? "Image layerinfos are different (PGP)"

		$CTR images rm ${ALPINE_DEC} &>/dev/null
		echo "PGP Decryption worked."
		sleep ${SLEEP_TIME}
	done

	echo "PASS: PGP Type of decryption after adding recipients"
	echo

	$CTR images rm ${ALPINE_ENC} ${ALPINE_DEC} &>/dev/null
	sleep ${SLEEP_TIME}
}

createJWEKeys() {
	echo "Generating keys for JWE encryption"

	PRIVKEYPEM=${WORKDIR}/mykey.pem
	PRIVKEYDER=${WORKDIR}/mykey.der
	PRIVKEYPK8PEM=${WORKDIR}/mykeypk8.pem
	PRIVKEYPK8DER=${WORKDIR}/mykeypk8.der

	PUBKEYPEM=${WORKDIR}/mypubkey.pem
	PUBKEYDER=${WORKDIR}/mypubkey.der

	PRIVKEY2PEM=${WORKDIR}/mykey2.pem
	PUBKEY2PEM=${WORKDIR}/mypubkey2.pem

	openssl genrsa -out ${PRIVKEYPEM} &>/dev/null
	failExit $? "Could not generate private key"

	openssl rsa -inform pem -outform der -in ${PRIVKEYPEM} -out ${PRIVKEYDER} &>/dev/null
	failExit $? "Could not convert private key to DER format"

	openssl pkcs8 -topk8 -nocrypt -inform pem -outform pem -in ${PRIVKEYPEM} -out ${PRIVKEYPK8PEM} &>/dev/null
	failExit $? "Could not convert private key to PKCS8 PEM format"

	openssl pkcs8 -topk8 -nocrypt -inform pem -outform der -in ${PRIVKEYPEM} -out ${PRIVKEYPK8DER} #&>/dev/null
	failExit $? "Could not convert private key to PKCS8 DER format"

	openssl rsa -inform pem -outform pem -pubout -in ${PRIVKEYPEM} -out ${PUBKEYPEM} &>/dev/null
	failExit $? "Could not write public key in PEM format"

	openssl rsa -inform pem -outform der -pubout -in ${PRIVKEYPEM} -out ${PUBKEYDER} &>/dev/null
	failExit $? "Could not write public key in PEM format"

	openssl genrsa -out ${PRIVKEY2PEM} &>/dev/null
	failExit $? "Could not generate 2nd private key"

	openssl rsa -inform pem -outform pem -pubout -in ${PRIVKEY2PEM} -out ${PUBKEY2PEM} &>/dev/null
	failExit $? "Could not write 2nd public key in PEM format"
}

testJWE() {
	createJWEKeys
	echo "Testing JWE type of encryption"

	for recipient in ${PUBKEYDER} ${PUBKEYPEM}; do

		$CTR images encrypt \
			--recipient ${recipient} \
			${ALPINE} ${ALPINE_ENC}
		failExit $? "Image encryption with JWE failed; public key: ${recipient}"

		LAYER_INFO_ENC="$($CTR images layerinfo ${ALPINE_ENC})"
		failExit $? "Image layerinfo on JWE encrypted image failed; public key: ${recipient}"

		diff <(echo "${LAYER_INFO}"     | gawk '{print $3}') \
		     <(echo "${LAYER_INFO_ENC}" | gawk '{print $3}' )
		failExit $? "Image layerinfo on JWE encrypted image shows differences in architectures"

		diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
		     <(echo -n "ENCRYPTIONjwe" )
		failExit $? "Image layerinfo on JWE encrypted image shows unexpected encryption"

		for privkey in ${PRIVKEYPEM} ${PRIVKEYDER} ${PRIVKEYPK8PEM} ${PRIVKEYPK8DER}; do
			$CTR images decrypt \
				--key ${privkey} \
				${ALPINE_ENC} ${ALPINE_DEC}
			failExit $? "Image decryption with JWE failed: private key: ${privkey}"

			LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
			failExit $? "Image layerinfo on decrypted image failed (JWE)"

			diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
			failExit $? "Image layerinfos are different (JWE)"

			$CTR images rm ${ALPINE_DEC} &>/dev/null
			echo "Decryption with ${privkey} worked."
			sleep ${SLEEP_TIME}
		done
		$CTR images rm ${ALPINE_ENC} &>/dev/null
		echo "Encryption with ${recipient} worked"
		sleep ${SLEEP_TIME}
	done

	$CTR images rm ${ALPINE_DEC} &>/dev/null
	sleep ${SLEEP_TIME}

	echo "PASS: JWE Type of encryption"
	echo

	echo "Testing adding a JWE recipient"
	$CTR images encrypt \
		--recipient ${recipient} \
		${ALPINE} ${ALPINE_ENC}
	failExit $? "Image encryption with JWE failed; public key: ${recipient}"

	$CTR images encrypt \
		--key ${PRIVKEYPEM} \
		--recipient ${PUBKEY2PEM} \
		${ALPINE_ENC}
	failExit $? "Adding recipient to JWE encrypted image failed"
	sleep ${SLEEP_TIME}

	for privkey in ${PRIVKEYPEM} ${PRIVKEY2PEM}; do
		$CTR images decrypt \
			--key ${privkey} \
			${ALPINE_ENC} ${ALPINE_DEC}
		failExit $? "Image decryption with JWE failed: private key: ${privkey}"

		LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
		failExit $? "Image layerinfo on decrypted image failed (JWE)"

		diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
		failExit $? "Image layerinfos are different (JWE)"

		$CTR images rm ${ALPINE_DEC} &>/dev/null
		echo "Decryption with ${privkey} worked."
		sleep ${SLEEP_TIME}
	done

	echo "PASS: JWE Type of decryption after adding recipients"
	echo

	$CTR images rm ${ALPINE_DEC} ${ALPINE_ENC} &>/dev/null
	sleep ${SLEEP_TIME}
}

setupPKCS7() {
	echo "Generating certs for PKCS7 encryption"

	CACERT=${WORKDIR}/cacert.pem
	CAKEY=${WORKDIR}/cacertkey.pem
	CLIENTCERT=${WORKDIR}/clientcert.pem
	CLIENTCERTKEY=${WORKDIR}/clientcertkey.pem
	CLIENTCERTCSR=${WORKDIR}/clientcert.csr

	CLIENT2CERT=${WORKDIR}/client2cert.pem
	CLIENT2CERTKEY=${WORKDIR}/client2certkey.pem
	CLIENT2CERTCSR=${WORKDIR}/client2cert.csr

	local CFG="
[req]
distinguished_name = dn
[dn]
[ext]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE
"
	openssl req -config <(echo "${CFG}") -newkey rsa:2048 \
		-x509 -extensions ext -days 365 -nodes -keyout ${CAKEY} -out ${CACERT} \
		-subj '/CN=foo/' &>/dev/null
	failExit $? "Could not create root CA's certificate"

	openssl genrsa -out ${CLIENTCERTKEY} 2048 &>/dev/null
	failExit $? "Could not create client key"
	openssl req -new -key ${CLIENTCERTKEY} -out ${CLIENTCERTCSR} -subj '/CN=bar/'
	failExit $? "Could not create client ertificate signing request"
	openssl x509 -req -in ${CLIENTCERTCSR} -CA ${CACERT} -CAkey ${CAKEY} -CAcreateserial \
		-out ${CLIENTCERT} -days 10 -sha256 &>/dev/null
	failExit $? "Could not create client certificate"

	openssl genrsa -out ${CLIENT2CERTKEY} 2048 &>/dev/null
	failExit $? "Could not create client2 key"
	openssl req -new -key ${CLIENT2CERTKEY} -out ${CLIENT2CERTCSR} -subj '/CN=bar/'
	failExit $? "Could not create client2 certificate signing request"
	openssl x509 -req -in ${CLIENT2CERTCSR} -CA ${CACERT} -CAkey ${CAKEY} -CAcreateserial \
		-out ${CLIENT2CERT} -days 10 -sha256 &>/dev/null
	failExit $? "Could not create client2 certificate"
}

testPKCS7() {
	setupPKCS7

	echo "Testing PKCS7 type of encryption"

	for recipient in ${CLIENTCERT}; do
		$CTR images encrypt \
			--recipient ${recipient} \
			${ALPINE} ${ALPINE_ENC}
		failExit $? "Image encryption with PKCS7 failed; public key: ${recipient}"

		LAYER_INFO_ENC="$($CTR images layerinfo ${ALPINE_ENC})"
		failExit $? "Image layerinfo on PKCS7 encrypted image failed; public key: ${recipient}"

		diff <(echo "${LAYER_INFO}"     | gawk '{print $3}') \
		     <(echo "${LAYER_INFO_ENC}" | gawk '{print $3}' )
		failExit $? "Image layerinfo on PKCS7 encrypted image shows differences in architectures"

		diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
		     <(echo -n "ENCRYPTIONpkcs7" )
		failExit $? "Image layerinfo on PKCS7 encrypted image shows unexpected encryption"

		for privKeyAndRecipient in "${CLIENTCERTKEY}:${CLIENTCERT}"; do
			privkey="$(echo ${privKeyAndRecipient} | cut -d ":" -f1)"
			recp="$(echo ${privKeyAndRecipient} | cut -d ":" -f2)"
			$CTR images decrypt \
				--recipient ${recipient} \
				--key ${privkey} \
				${ALPINE_ENC} ${ALPINE_DEC}
			failExit $? "Image decryption with PKCS7 failed: private key: ${privkey}"

			LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
			failExit $? "Image layerinfo on decrypted image failed (PKCS7)"

			diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
			failExit $? "Image layerinfos are different (PKCS7)"

			$CTR images rm ${ALPINE_DEC} &>/dev/null
			echo "Decryption with ${privkey} worked."
			sleep ${SLEEP_TIME}
		done
		$CTR images rm ${ALPINE_ENC} &>/dev/null
		echo "Encryption with ${recipient} worked"
		sleep ${SLEEP_TIME}
	done

	echo "PASS: PKCS7 Type of encryption"
	echo

	echo "Testing adding a PKCS7 recipient"
	$CTR images encrypt \
		--recipient ${CLIENTCERT} \
		${ALPINE} ${ALPINE_ENC}
	failExit $? "Image encryption with PKCS7 failed; public key: ${recipient}"

	$CTR images encrypt \
		--key ${CLIENTCERTKEY} \
		--dec-recipient ${CLIENTCERT} \
		--recipient ${CLIENT2CERT} \
		${ALPINE_ENC}
	failExit $? "Adding recipient to PKCS7 encrypted image failed"
	sleep ${SLEEP_TIME}

	for privKeyAndRecipient in "${CLIENTCERTKEY}:${CLIENTCERT}" "${CLIENT2CERTKEY}:${CLIENT2CERT}"; do
		privkey="$(echo ${privKeyAndRecipient} | cut -d ":" -f1)"
		recp="$(echo ${privKeyAndRecipient} | cut -d ":" -f2)"
		$CTR images decrypt \
			--key ${privkey} \
			--recipient ${recp} \
			${ALPINE_ENC} ${ALPINE_DEC}
		failExit $? "Image decryption with PKCS7 failed: private key: ${privkey}"

		LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
		failExit $? "Image layerinfo on decrypted image failed (PKCS7)"

		diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
		failExit $? "Image layerinfos are different (PKCS7)"

		$CTR images rm ${ALPINE_DEC} &>/dev/null
		echo "Decryption with ${privkey} worked."
		sleep ${SLEEP_TIME}
	done

	echo "PASS: PKCS7 Type of decryption after adding recipients"
	echo

	$CTR images rm ${ALPINE_DEC} ${ALPINE_ENC} &>/dev/null
	sleep ${SLEEP_TIME}
}

testPGPandJWEandPKCS7() {
	local ctr

	createJWEKeys
	setupPGP
	setupPKCS7

	echo "Testing large recipient list"
	$CTR images encrypt \
		--gpg-homedir ${GPGHOMEDIR} \
		--gpg-version 2 \
		--recipient testkey1@key.org \
		--recipient testkey2@key.org \
		--recipient ${PUBKEYPEM} \
		--recipient ${PUBKEY2PEM} \
		--recipient ${CLIENTCERT} \
		--recipient ${CLIENT2CERT} \
		${ALPINE} ${ALPINE_ENC}
	failExit $? "Image encryption to many different recipients failed"
	LAYER_INFO_ENC="$($CTR images layerinfo ${ALPINE_ENC})"
	failExit $? "Image layerinfo on multi-recipient encrypted image failed; public key: ${recipient}"

	diff <(echo "${LAYER_INFO}"     | gawk '{print $3}') \
	     <(echo "${LAYER_INFO_ENC}" | gawk '{print $3}' )
	failExit $? "Image layerinfo on multi-recipient encrypted image shows differences in architectures"

	diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
	     <(echo -n "ENCRYPTIONjwe,pgp,pkcs7" )

	$CTR images rm ${ALPINE_ENC} &>/dev/null
	echo "Encryption to multiple different types of recipients worked."
	sleep ${SLEEP_TIME}


	echo "Testing adding first PGP and then JWE and PKCS7 recipients"
	$CTR images encrypt \
		--gpg-homedir ${GPGHOMEDIR} \
		--gpg-version 2 \
		--recipient testkey1@key.org \
		${ALPINE} ${ALPINE_ENC}
	failExit $? "Image encryption with PGP failed; recipient: testkey1@key.org"
	sleep ${SLEEP_TIME}

	ctr=0
	for recipient in ${PUBKEYPEM} testkey2@key.org ${PUBKEY2PEM} ${CLIENTCERT} ${CLIENT2CERT}; do
		$CTR images encrypt \
			--gpg-homedir ${GPGHOMEDIR} \
			--gpg-version 2 \
			--recipient ${recipient} \
			--key <(echo "${GPGTESTKEY1}" | base64 -d) \
			${ALPINE_ENC}
		failExit $? "Adding ${recipient} failed"
		sleep ${SLEEP_TIME}

		LAYER_INFO_ENC="$($CTR images layerinfo ${ALPINE_ENC})"
		failExit $? "Image layerinfo on multi-recipient encrypted image failed; public key: ${recipient}"

		diff <(echo "${LAYER_INFO}"     | gawk '{print $3}') \
		     <(echo "${LAYER_INFO_ENC}" | gawk '{print $3}' )
		failExit $? "Image layerinfo on multi-recipient encrypted image shows differences in architectures"

		if [ $ctr -lt 3 ]; then
			diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
			     <(echo -n "ENCRYPTIONjwe,pgp" )
		else
			diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
			     <(echo -n "ENCRYPTIONjwe,pgp,pkcs7" )
		fi
		failExit $? "Image layerinfo on JWE encrypted image shows unexpected encryption (ctr=$ctr)"
		ctr=$((ctr + 1))
	done

	# everyone must be able to decrypt it -- first JWE ...
	for privkey in ${PRIVKEYPEM} ${PRIVKEY2PEM}; do
		$CTR images decrypt \
			--key ${privkey} \
			${ALPINE_ENC} ${ALPINE_DEC}
		failExit $? "Image decryption with JWE failed: private key: ${privkey}"
		sleep ${SLEEP_TIME}

		LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
		failExit $? "Image layerinfo on decrypted image failed (JWE)"

		diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
		failExit $? "Image layerinfos are different (JWE)"

		$CTR images rm ${ALPINE_DEC} &>/dev/null
		echo "JWE Decryption with ${privkey} worked."
		sleep ${SLEEP_TIME}
	done

	# ... then pgp
	for privkey in ${GPGTESTKEY1} ${GPGTESTKEY2}; do
		$CTR images decrypt \
			--gpg-homedir ${GPGHOMEDIR} \
			--gpg-version 2 \
			--key <(echo "${privkey}" | base64 -d) \
			${ALPINE_ENC} ${ALPINE_DEC}
		failExit $? "Image decryption with PGP failed"
		sleep ${SLEEP_TIME}

		LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
		failExit $? "Image layerinfo on decrypted image failed (PGP)"

		diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
		failExit $? "Image layerinfos are different (PGP)"

		$CTR images rm ${ALPINE_DEC} &>/dev/null
		echo "PGP Decryption worked."
		sleep ${SLEEP_TIME}
	done

	# and then pkcs7
	for privKeyAndRecipient in "${CLIENTCERTKEY}:${CLIENTCERT}" "${CLIENT2CERTKEY}:${CLIENT2CERT}"; do
		privkey="$(echo ${privKeyAndRecipient} | cut -d ":" -f1)"
		recp="$(echo ${privKeyAndRecipient} | cut -d ":" -f2)"
		$CTR images decrypt \
			--key ${privkey} \
			--recipient ${recp} \
			${ALPINE_ENC} ${ALPINE_DEC}
		failExit $? "Image decryption with PKCS7 failed: private key: ${privkey}"

		LAYER_INFO_DEC="$($CTR images layerinfo ${ALPINE_DEC})"
		failExit $? "Image layerinfo on decrypted image failed (PKCS7)"

		diff <(echo "${LAYER_INFO}") <(echo "${LAYER_INFO_DEC}")
		failExit $? "Image layerinfos are different (PKCS7)"

		$CTR images rm ${ALPINE_DEC} &>/dev/null
		echo "PKCS7 decryption with ${privkey} worked."
		sleep ${SLEEP_TIME}
	done

	$CTR images rm ${ALPINE_DEC} ${ALPINE_ENC} &>/dev/null
	sleep ${SLEEP_TIME}


	echo "Testing adding first JWE and then PGP and PKCS7 recipients"
	$CTR images encrypt \
		--recipient ${PUBKEYPEM} \
		${ALPINE} ${ALPINE_ENC}
	failExit $? "Image encryption with JWE failed; public key: ${recipient}"
	sleep ${SLEEP_TIME}

	ctr=0
	for recipient in testkey1@key.org testkey2@key.org ${PUBKEY2PEM} ${CLIENTCERT} ${CLIENT2CERT}; do
		$CTR images encrypt \
			--gpg-homedir ${GPGHOMEDIR} \
			--gpg-version 2 \
			--recipient ${recipient} \
			--key ${PRIVKEYPEM} \
			${ALPINE_ENC}
		failExit $? "Adding ${recipient} failed"
		sleep ${SLEEP_TIME}

		LAYER_INFO_ENC="$($CTR images layerinfo ${ALPINE_ENC})"
		failExit $? "Image layerinfo on JWE encrypted image failed; public key: ${recipient}"

		diff <(echo "${LAYER_INFO}"     | gawk '{print $3}') \
		     <(echo "${LAYER_INFO_ENC}" | gawk '{print $3}' )
		failExit $? "Image layerinfo on JWE encrypted image shows differences in architectures"

		if [ $ctr -lt 3 ]; then
			diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
			     <(echo -n "ENCRYPTIONjwe,pgp" )
		else
			diff <(echo "${LAYER_INFO_ENC}" | gawk '{print $5}' | sort | uniq | tr -d '\n') \
			     <(echo -n "ENCRYPTIONjwe,pgp,pkcs7" )
		fi
		failExit $? "Image layerinfo on JWE encrypted image shows unexpected encryption"
		ctr=$((ctr + 1))
	done

	echo "PASS: Test with JWE, PGP, and PKCS7 recipients"

	$CTR images rm ${ALPINE_DEC} ${ALPINE_ENC} &>/dev/null
	sleep ${SLEEP_TIME}
}

testPGP
testJWE
testPKCS7
testPGPandJWEandPKCS7

