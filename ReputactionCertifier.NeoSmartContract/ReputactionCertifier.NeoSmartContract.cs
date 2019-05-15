using Neo.SmartContract.Framework;
using Neo.SmartContract.Framework.Services.Neo;
using System.ComponentModel;
using System.Numerics;

////////////////////////////////////////////////////////////////////////////////////////////////////
// namespace: Reputaction
//
// summary:	This is the namespace used for the code of the Reputaction company, which innovates in decentralized
// trust (blockchain, online reputation, relational value, harden crypto wallets...). For more
// information about Reputaction, please consult https://www.reputaction.com
////////////////////////////////////////////////////////////////////////////////////////////////////

namespace Reputaction
{
    ////////////////////////////////////////////////////////////////////////////////////////////////////
    /// <summary>
    ///     The ReputactionCertifierSmartContract provides methods to certify that some information
    ///     has been disclosed by the owner of a public key by adding permanently a signed record of
    ///     the information on the NEO blockchain. It is deployed on the NEO public MainNet
    ///     blockchain with contract ScriptHash: d82dd7188dc6dafb03d3df51783fde82a8f37359. Knowing
    ///     the information, it is possible to compute the SHA256 hash of that information to
    ///     retrieve who recorded it and when. For example, when a user of the Reputaction relational
    ///     value marketplace adds her/his contribution to a product, it is also recorded via this
    ///     smartcontract. Although at time of smartcontract deployment the relational value
    ///     marketplace records the contribution for the user, in the future the user will be able to
    ///     record directly via her/his crypto wallet to further increase decentralization and
    ///     transparency. On one hand, the smartcontract doesn't implement any information delete
    ///     method in order to avoid the deletion of cheating information and to achieve the highest
    ///     level of transparency. Anybody can double-check which information has been disclosed and
    ///     when. However, on the other hand, be careful not to record personal information in order
    ///     to comply to privacy rights and laws such as GDPR. For this reason, the Reputaction
    ///     relational value marketplace records a URL that contains information about the
    ///     contributor but that will be deleted if the user requests her/his right to be forgotten.
    ///     If the users themselves record directly their information via their own crypto wallets
    ///     and key pair, they are reminded that they shouldn't add personal information because they
    ///     won't be able to delete it on the blockchain afterwards. Reputaction patent pending
    ///     hardened crypto-wallet will even allow the contributors to transact offline. This
    ///     smartcontract provides also helpers methods to disclose that someone controls a public
    ///     key, when it was set alive, as well as link two pseudonyms and pass KYC/AML checks on
    ///     partner KYC/AML providers such as KYCBench. A list of trustworthy partners as official
    ///     recorders is also maintained in addition to Reputaction because it will help to compute
    ///     the trust in the recorded information. Letting the users sign directly their product
    ///     contributions from their crypto wallet and having other recorders than Reputaction will
    ///     create a fully decentralized relational value marketplace. In the future, relational
    ///     value data will also be served and managed by Reputaction through an Application
    ///     Programming Interface (API). That API may require Reputaction utility tokens for costly
    ///     tasks and better reward the products contributors in addition to give a price premium and
    ///     higher visibility to their products thanks to the displayed relational value information.
    ///     More information about Reputaction relational value decentralized marketplace and
    ///     hardened crypto wallet on https://app.reputaction.com,
    ///     https://github.com/reputaction/reputaction-certifier-neo-smart-contract and
    ///     https://www.reputaction.com.
    /// </summary>
    ///
    /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
    ////////////////////////////////////////////////////////////////////////////////////////////////////

    public class ReputactionCertifierSmartContract : SmartContract
    {
        /// <summary>
        /// A static read-only parameter used to return that the call failed.
        /// </summary>
        public static readonly byte[] Failed = "Failed!".AsByteArray();

        /// <summary>
        /// A static read-only parameter used to return that the no method was called.
        /// </summary>
        public static readonly byte[] NoMethodCalled = "No method called!".AsByteArray();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     A static read-only parameter used to return that no signature was provided.
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        public static readonly byte[] NoSignature = "No signature!".AsByteArray();

        /// <summary>
        /// A static read-only parameter used to return that it was not found.
        /// </summary>
        public static readonly byte[] NotFound = "Not found!".AsByteArray();

        /// <summary>
        /// The first initial address of the key pairs used by Reputaction to certify.
        /// </summary>
        public static readonly byte[] ReputactionFirstCertifierAddressScriptHash = "AdT39KQarGUEUKkeGvK2DcUeLbgQmrA7Lo".ToScriptHash();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     The second initial address of the key pairs used by Reputaction to certify.
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        public static readonly byte[] ReputactionSecondCertifierAddressScriptHash = "AMMgjnpk6LwJEXzxbBxCM9h4ud11u9kwT1".ToScriptHash();

        /// <summary>
        /// The third initial address of the key pairs used by Reputaction to certify.
        /// </summary>
        public static readonly byte[] ReputactionThirdCertifierAddressScriptHash = "AR2dPzgGPTbhYcPJ4PZRvme3guryNWs7Wt".ToScriptHash();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     A static read-only parameter used to separate fields in returns and records.
        /// </summary>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        public static readonly byte[] Separator = "***".AsByteArray();

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the provided public key is known to be one controlled by Reputaction.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pubKey">   The public key to be checked as byte[]. </param>
        ///
        /// <returns>   True if current caller is Reputaction, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        private static bool IsCurrentCallerReputaction(byte[] pubKey)
        {
            bool isReputaction = false;
            if (IsReputactionCertifierPublicKey(pubKey))
            {
                if (Runtime.CheckWitness(pubKey))
                {
                    isReputaction = true;
                }
            }
            else
            {
                if (Runtime.CheckWitness(ReputactionFirstCertifierAddressScriptHash) ||
                Runtime.CheckWitness(ReputactionSecondCertifierAddressScriptHash) ||
                Runtime.CheckWitness(ReputactionThirdCertifierAddressScriptHash))
                {
                    isReputaction = true;
                }
            }
            return isReputaction;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Return true if the new KYC/AML certifier partner public key has been successfully added
        ///     to the list of official KYC/AML providers recognized by Reputaction.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="addingCertifierPubKey">            The certifier public key as byte[]. </param>
        /// <param name="toBeAddedKycAmlCertifierPubKey">   The public key to be added as byte[]. </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("addNewKycAmlCertifierPublicKey")]
        public static bool AddNewKycAmlCertifierPublicKey(byte[] addingCertifierPubKey, byte[] toBeAddedKycAmlCertifierPubKey)
        {
            bool added = false;
            if (IsCurrentCallerReputaction(addingCertifierPubKey))
            {
                StorageMap kycAmlCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(kycAmlCertifierPublicKeys));
                kycAmlCertifierPublicKeys.Put(SmartContract.Sha256(toBeAddedKycAmlCertifierPubKey), toBeAddedKycAmlCertifierPubKey);
                added = true;
            }
            return added;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the new recorder partner public key has been successfully added to the
        ///     list of partners recognized as official recorders by Reputaction.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="addingCertifierPubKey">            The certifier public key as byte[]. </param>
        /// <param name="toBeAddedPartnerRecorderPubKey">
        ///     The public key of the partner recorder to be added as byte[].
        /// </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("addNewPartnerRecorderCertifierPublicKey")]
        public static bool AddNewPartnerRecorderCertifierPublicKey(byte[] addingCertifierPubKey, byte[] toBeAddedPartnerRecorderPubKey)
        {
            bool added = false;
            if (IsCurrentCallerReputaction(addingCertifierPubKey))
            {
                {
                    StorageMap partnerRecorderCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(partnerRecorderCertifierPublicKeys));
                    partnerRecorderCertifierPublicKeys.Put(SmartContract.Sha256(toBeAddedPartnerRecorderPubKey), toBeAddedPartnerRecorderPubKey);
                    added = true;
                }
            }
            return added;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the provided public key has been successfully added to the list of public
        ///     keys representing Reputaction.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="addingCertifierPubKey">                The certifier public key as byte[]. </param>
        /// <param name="toBeAddedReputactionCertifierPubKey">
        ///     The new public key to represent Reputaction as byte[].
        /// </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("addNewReputactionCertifierPublicKey")]
        public static bool AddNewReputactionCertifierPublicKey(byte[] addingCertifierPubKey, byte[] toBeAddedReputactionCertifierPubKey)
        {
            bool added = false;
            if (IsCurrentCallerReputaction(addingCertifierPubKey))
            {
                StorageMap reputactionCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(reputactionCertifierPublicKeys));
                reputactionCertifierPublicKeys.Put(SmartContract.Sha256(toBeAddedReputactionCertifierPubKey), toBeAddedReputactionCertifierPubKey);
                added = true;
            }
            return added;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns a timestamp of when SetAlive was successfully carried out for the provided public
        ///     key.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pseudonymPubKey">
        ///     The public key of the pseudonym to be checked as byte[].
        /// </param>
        ///
        /// <returns>   A byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("checkWhenPseudonymWasAlive")]
        public static byte[] CheckWhenPseudonymWasAlive(byte[] pseudonymPubKey)
        {
            StorageMap alives = Storage.CurrentContext.CreateMap(nameof(alives));
            return alives.Get(pseudonymPubKey);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns the number of times the provided public key has been successfully KYC/AMLed
        ///     (revoked aren't counted)
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pubKey">   The public key of the pseudonym to be checked as byte[]. </param>
        ///
        /// <returns>   The total number of KYC AML certifications. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("CountKycAmled")]
        public static BigInteger CountKycAmled(byte[] pubKey)
        {
            uint count = 0;
            Iterator<byte[], byte[]> keys = Storage.Find(Storage.CurrentContext, SmartContract.Sha256(pubKey));
            for (; keys.Next();)
            {
                if (!IsRevokedKycAmlCertificationByKey(keys.Key))
                {
                    count = count + 1;
                }
            }
            return count;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns the number of times records with the provided information has been found.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="information">  The information to be checked as byte[]. </param>
        ///
        /// <returns>   The total number of records by information. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("countRecordsByInformation")]
        public static BigInteger CountRecordsByInformation(byte[] information)
        {
            uint count = 0;
            Iterator<byte[], byte[]> records = Storage.Find(Storage.CurrentContext, SmartContract.Sha256(information));
            for (; records.Next();)
            {
                count = count + 1;
            }
            return count;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns the number of times records with keys with such prefix have been found.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="prefix">   The prefix to be checked as byte[]. </param>
        ///
        /// <returns>   The total number of records by prefix. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("countRecordsByPrefix")]
        public static BigInteger CountRecordsByPrefix(byte[] prefix)
        {
            uint count = 0;
            Iterator<byte[], byte[]> records = Storage.Find(Storage.CurrentContext, prefix);
            for (; records.Next();)
            {
                count = count + 1;
            }
            return count;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Deletes the KYC/AML certifier from the list validated by Reputaction given the public key
        ///     representing Reputaction and the KYC/AML public key to be deleted.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="certifierPubKey">                  The certifier public key as byte[]. </param>
        /// <param name="toBeDeletedKycAmlCertifierPubKey">
        ///     The public key of the KYC AML provider to be deleted as byte[].
        /// </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("deleteKycAmlCertifierPublicKey")]
        public static bool DeleteKycAmlCertifierPublicKey(byte[] certifierPubKey, byte[] toBeDeletedKycAmlCertifierPubKey)
        {
            bool deleted = false;
            if (IsCurrentCallerReputaction(certifierPubKey))
            {
                StorageMap kycAmlCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(kycAmlCertifierPublicKeys));
                kycAmlCertifierPublicKeys.Delete(SmartContract.Sha256(toBeDeletedKycAmlCertifierPubKey));
                deleted = true;
            }
            return deleted;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Deletes the recorder partner from the list validated by Reputaction given the public key
        ///     representing Reputaction and the recorder partner public key to be deleted.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="certifierPubKey">
        ///     The certifier public key as byte[].
        /// </param>
        /// <param name="toBeDeletedPartnerRecorderCertifierPubKey">
        ///     The public key of the recorder partner to be deleted as byte[].
        /// </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("deletePartnerRecorderCertifierPublicKey")]
        public static bool DeletePartnerRecorderCertifierPublicKey(byte[] certifierPubKey, byte[] toBeDeletedPartnerRecorderCertifierPubKey)
        {
            bool deleted = false;
            if (IsCurrentCallerReputaction(certifierPubKey))
            {
                StorageMap partnerRecorderCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(partnerRecorderCertifierPublicKeys));
                partnerRecorderCertifierPublicKeys.Delete(SmartContract.Sha256(toBeDeletedPartnerRecorderCertifierPubKey));
                deleted = true;
            }
            return deleted;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Deletes the public key representing Reputaction from the list validated by Reputaction
        ///     given the public key representing Reputaction and the public key to be deleted.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="certifierPubKey">
        ///     The certifier public key as byte[].
        /// </param>
        /// <param name="toBeDeletedReputactionCertifierPubKey">
        ///     The public key representing Reputaction to be deleted as byte[].
        /// </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("deleteReputactionCertifierPublicKey")]
        public static bool DeleteReputactionCertifierPublicKey(byte[] certifierPubKey, byte[] toBeDeletedReputactionCertifierPubKey)
        {
            bool deleted = false;
            if (IsCurrentCallerReputaction(certifierPubKey))
            {
                StorageMap reputactionCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(reputactionCertifierPublicKeys));
                reputactionCertifierPublicKeys.Put(SmartContract.Sha256(toBeDeletedReputactionCertifierPubKey), toBeDeletedReputactionCertifierPubKey);
                deleted = true;
            }
            return deleted;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the given public key is one in the list of validated KYC/AML providers
        ///     public keys by Reputaction.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="potentialKycAmlCertifierPubKey">   The public key to checked as byte[]. </param>
        ///
        /// <returns>   True if KYC AML certifier public key, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("IsKycAmlCertifierPublicKey")]
        public static bool IsKycAmlCertifierPublicKey(byte[] potentialKycAmlCertifierPubKey)
        {
            bool isCertifier = false;
            StorageMap kycAmlCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(kycAmlCertifierPublicKeys));
            if (kycAmlCertifierPublicKeys.Get(SmartContract.Sha256(potentialKycAmlCertifierPubKey)).Length != 0)
            {
                isCertifier = true;
            }
            return isCertifier;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the two pseudonyms have been successfully linked with LinkPseudonyms.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pseudonym1PubKey"> The public key of the first pseudonym as byte[]. </param>
        /// <param name="pseudonym2PubKey"> The public key of the second pseudonym as byte[]. </param>
        ///
        /// <returns>   True if linked pseudonyms, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("isLinkedPseudonyms")]
        public static bool IsLinkedPseudonyms(byte[] pseudonym1PubKey, byte[] pseudonym2PubKey)
        {
            bool linked = false;
            if (pseudonym1PubKey.Equals(pseudonym2PubKey))
            {
                linked = true;
            }
            else
            {
                StorageMap linkedPseudonyms = Storage.CurrentContext.CreateMap(nameof(linkedPseudonyms));
                byte[] key = pseudonym1PubKey.Concat(pseudonym2PubKey);
                byte[] otherSideKey = pseudonym2PubKey.Concat(pseudonym1PubKey);
                if ((linkedPseudonyms.Get(key).Length != 0) && (linkedPseudonyms.Get(otherSideKey).Length != 0))
                {
                    linked = true;
                }
            }
            return linked;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the public key is in the list of recorder partners public keys.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="potentialPartnerRecorderCertifierPubKey">
        ///     The public key of the potential recorder partner as byte[].
        /// </param>
        ///
        /// <returns>   True if partner recorder certifier public key, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("IsPartnerRecorderCertifierPublicKey")]
        public static bool IsPartnerRecorderCertifierPublicKey(byte[] potentialPartnerRecorderCertifierPubKey)
        {
            bool isCertifier = false;
            StorageMap partnerRecorderCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(partnerRecorderCertifierPublicKeys));
            if (partnerRecorderCertifierPublicKeys.Get(SmartContract.Sha256(potentialPartnerRecorderCertifierPubKey)).Length != 0)
            {
                isCertifier = true;
            }
            return isCertifier;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns true if the record was recorded by a recorder partner. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="recordKey">    The record key as byte[]. </param>
        ///
        /// <returns>   True if recorded by partner recorder, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("IsRecordedByPartnerRecorder")]
        public static bool IsRecordedByPartnerRecorder(byte[] recordKey)
        {
            bool isRecorderByPartnerRecorder = false;
            byte[] pseudonymRecorder = RetrievePseudonymByKey(recordKey);
            if (IsPartnerRecorderCertifierPublicKey(pseudonymRecorder))
            {
                isRecorderByPartnerRecorder = true;
            }
            return isRecorderByPartnerRecorder;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns true if the record was recorded by Reputaction. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="recordKey">    The record key as byte[]. </param>
        ///
        /// <returns>   True if recorded by reputaction, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("IsRecordedByReputaction")]
        public static bool IsRecordedByReputaction(byte[] recordKey)
        {
            bool isRecorderByReputaction = false;
            byte[] pseudonymRecorder = RetrievePseudonymByKey(recordKey);
            if (IsReputactionCertifierPublicKey(pseudonymRecorder))
            {
                isRecorderByReputaction = true;
            }
            return isRecorderByReputaction;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns true if the record is older than the give time (in Unix time) </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The record key as byte[]. </param>
        /// <param name="time"> The time as Unix time as Little-Endian ByteArray. </param>
        ///
        /// <returns>   True if record older than, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("IsRecordOlderThan")]
        public static bool IsRecordOlderThan(byte[] key, BigInteger time)
        {
            bool older = false;
            StorageMap timestamps = Storage.CurrentContext.CreateMap(nameof(timestamps));
            byte[] timestamp = timestamps.Get(key);
            if (timestamp.AsBigInteger() < time)
            {
                older = true;
            }
            return older;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns true is the given public key is one representing Reputaction. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="potentialReputactionCertifierPubKey">
        ///     The public key to be checked as byte[].
        /// </param>
        ///
        /// <returns>   True if reputaction certifier public key, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("isReputactionCertifierPublicKey")]
        public static bool IsReputactionCertifierPublicKey(byte[] potentialReputactionCertifierPubKey)
        {
            bool isCertifier = false;
            StorageMap reputactionCertifierPublicKeys = Storage.CurrentContext.CreateMap(nameof(reputactionCertifierPublicKeys));
            if (reputactionCertifierPublicKeys.Get(SmartContract.Sha256(potentialReputactionCertifierPubKey)).Length != 0)
            {
                isCertifier = true;
            }
            return isCertifier;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns true if the given KYC/AML certification is revoked given its key. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="kycAmlCertificationKey">
        ///     The public key of the KYC AML certification to be checked as byte[].
        /// </param>
        ///
        /// <returns>   True if revoked KYC AML certification by key, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("isRevokedKycAmlCertificationByKey")]
        public static bool IsRevokedKycAmlCertificationByKey(byte[] kycAmlCertificationKey)
        {
            bool revoked = false;
            StorageMap revokedPubKeyKycAmlCertifications = Storage.CurrentContext.CreateMap(nameof(revokedPubKeyKycAmlCertifications));
            byte[] timestamp = revokedPubKeyKycAmlCertifications.Get(kycAmlCertificationKey);
            if (timestamp.Length != 0)
            {
                revoked = true;
            }
            return revoked;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the given public key has at least one valid KYC/AML certification.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pubKey">   The public key to checked as byte[]. </param>
        ///
        /// <returns>   True if valid KYC AML, false if not. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("isValidKycAmled")]
        public static bool IsValidKycAmled(byte[] pubKey)
        {
            bool validKycAmled = false;
            if (CountKycAmled(pubKey) > 0)
            {
                validKycAmled = true;
            }
            return validKycAmled;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns true if the two public keys have been successfully linked. It must be called
        ///     twice from each public key as witness (pub1 as witness, pub2) then (pub2 as witness, pub1)
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pseudonym1PubKey"> The public key of the first pseudonym as byte[]. </param>
        /// <param name="pseudonym2PubKey"> The public key of the second pseudonym as byte[]. </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("linkPseudonyms")]
        public static bool LinkPseudonyms(byte[] pseudonym1PubKey, byte[] pseudonym2PubKey)
        {
            bool linked = false;
            if (Runtime.CheckWitness(pseudonym1PubKey))
            {
                StorageMap linkedPseudonyms = Storage.CurrentContext.CreateMap(nameof(linkedPseudonyms));
                byte[] key = pseudonym1PubKey.Concat(pseudonym2PubKey);
                byte[] otherSideKey = pseudonym2PubKey.Concat(pseudonym1PubKey);
                linkedPseudonyms.Put(key, 1);
                if (linkedPseudonyms.Get(otherSideKey).Length != 0)
                {
                    linked = true;
                }
            }
            return linked;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Main entry-point for this NEO smart contract. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="method">   A command-line argument text string. </param>
        /// <param name="args">     An array of command-line argument objects. </param>
        ///
        /// <returns>   No method called or the result of the called method. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        public static object Main(string method, object[] args)
        {
            if (Runtime.Trigger == TriggerType.Application)
            {
                if (method == "addNewKycAmlCertifierPublicKey")
                {
                    return AddNewKycAmlCertifierPublicKey((byte[])args[0], (byte[])args[1]);
                }

                if (method == "addNewPartnerRecorderCertifierPublicKey")
                {
                    return AddNewPartnerRecorderCertifierPublicKey((byte[])args[0], (byte[])args[1]);
                }

                if (method == "addNewReputactionCertifierPublicKey")
                {
                    return AddNewReputactionCertifierPublicKey((byte[])args[0], (byte[])args[1]);
                }

                if (method == "checkWhenPseudonymWasAlive")
                {
                    return CheckWhenPseudonymWasAlive((byte[])args[0]);
                }

                if (method == "countKycAmled")
                {
                    return CountKycAmled((byte[])args[0]);
                }

                if (method == "countRecordsByInformation")
                {
                    return CountRecordsByInformation((byte[])args[0]);
                }

                if (method == "countRecordsByPrefix")
                {
                    return CountRecordsByPrefix((byte[])args[0]);
                }

                if (method == "deleteKycAmlCertifierPublicKey")
                {
                    return DeleteKycAmlCertifierPublicKey((byte[])args[0], (byte[])args[1]);
                }

                if (method == "deletePartnerRecorderCertifierPublicKey")
                {
                    return DeletePartnerRecorderCertifierPublicKey((byte[])args[0], (byte[])args[1]);
                }

                if (method == "deleteReputactionCertifierPublicKey")
                {
                    return DeleteReputactionCertifierPublicKey((byte[])args[0], (byte[])args[1]);
                }

                if (method == "isKycAmlCertifierPublicKey")
                {
                    return IsKycAmlCertifierPublicKey((byte[])args[0]);
                }

                if (method == "isLinkedPseudonyms")
                {
                    return IsLinkedPseudonyms((byte[])args[0], (byte[])args[1]);
                }

                if (method == "isPartnerRecorderCertifierPublicKey")
                {
                    return IsPartnerRecorderCertifierPublicKey((byte[])args[0]);
                }

                if (method == "isRecordedByPartnerRecorder")
                {
                    return IsRecordedByPartnerRecorder((byte[])args[0]);
                }

                if (method == "isRecordedByReputaction")
                {
                    return IsRecordedByReputaction((byte[])args[0]);
                }

                if (method == "isRecordOlderThan")
                {
                    return IsRecordOlderThan((byte[])args[0], (BigInteger)args[1]);
                }

                if (method == "isReputactionCertifierPublicKey")
                {
                    return IsReputactionCertifierPublicKey((byte[])args[0]);
                }

                if (method == "isRevokedKycAmlCertificationByKey")
                {
                    return IsRevokedKycAmlCertificationByKey((byte[])args[0]);
                }

                if (method == "isValidKycAmled")
                {
                    return IsValidKycAmled((byte[])args[0]);
                }

                if (method == "linkPseudonyms")
                {
                    return LinkPseudonyms((byte[])args[0], (byte[])args[1]);
                }

                if (method == "passKycAmlWithCertificates")
                {
                    return PassKycAmlWithCertificates((byte[])args[0], (byte[])args[1], (byte[])args[2]);
                }

                if (method == "passKycAmlWithoutCertificates")
                {
                    return PassKycAmlWithoutCertificates((byte[])args[0], (byte[])args[1]);
                }

                if (method == "recordWithSignature")
                {
                    return RecordWithSignature((byte[])args[0], (byte[])args[1], (byte[])args[2]);
                }

                if (method == "recordWithoutSignature")
                {
                    return RecordWithoutSignature((byte[])args[0], (byte[])args[1]);
                }

                if (method == "retrieveInformationByKey")
                {
                    return RetrieveInformationByKey((byte[])args[0]);
                }

                if (method == "retrieveKycAmlCertificationCertificatesByKey")
                {
                    return RetrieveKycAmlCertificationCertificatesByKey((byte[])args[0]);
                }

                if (method == "retrieveKycAmlCertificationCertifierByKey")
                {
                    return RetrieveKycAmlCertificationCertifierByKey((byte[])args[0]);
                }

                if (method == "retrieveKycAmlCertificationKeyByPubKeyAndNumber")
                {
                    return RetrieveKycAmlCertificationKeyByPubKeyAndNumber((byte[])args[0], (BigInteger)args[1]);
                }

                if (method == "retrievePseudonymByKey")
                {
                    return RetrievePseudonymByKey((byte[])args[0]);
                }

                if (method == "retrieveRecordByKey")
                {
                    return RetrieveRecordByKey((byte[])args[0]);
                }

                if (method == "retrieveRecordKeyByInformationAndNumber")
                {
                    return RetrieveRecordKeyByInformationAndNumber((byte[])args[0], (BigInteger)args[1]);
                }

                if (method == "retrieveRecordKeyByPrefixAndNumber")
                {
                    return RetrieveRecordKeyByPrefixAndNumber((byte[])args[0], (BigInteger)args[1]);
                }

                if (method == "retrieveSignatureByKey")
                {
                    return RetrieveSignatureByKey((byte[])args[0]);
                }

                if (method == "retrieveTimestampByKey")
                {
                    return RetrieveTimestampByKey((byte[])args[0]);
                }

                if (method == "revokeKycAmlCertificationByKey")
                {
                    return RevokeKycAmlCertificationByKey((byte[])args[0], (byte[])args[1]);
                }

                if (method == "setAlive")
                {
                    return SetAlive((byte[])args[0]);
                }
            }

            return NoMethodCalled;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns Failed! or the key of the KYC/AML certification given the public key of the
        ///     pseudonym KYC/AMLed, the KYC/AML certifier public key along with certificates.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="passingKycAmlPseudonmyPubKey">
        ///     The public key of the pseudonym who has successfully passed KYC AML as byte[].
        /// </param>
        /// <param name="kycAmlCertifierPubKey">
        ///     The public of the KYC AML certifier who checked the KYC AML of the pseudonym as byte[].
        /// </param>
        /// <param name="certificates">
        ///     Certificates about the KYC AML certification.
        /// </param>
        ///
        /// <returns>   The key of the new KYC AML certification as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("passKycAmlWithCertificates")]
        public static byte[] PassKycAmlWithCertificates(byte[] passingKycAmlPseudonmyPubKey, byte[] kycAmlCertifierPubKey, byte[] certificates)
        {
            byte[] key = Failed;
            if (IsKycAmlCertifierPublicKey(kycAmlCertifierPubKey) && Runtime.CheckWitness(kycAmlCertifierPubKey))
            {
                key = PassKycAmlWithoutCertificates(passingKycAmlPseudonmyPubKey, kycAmlCertifierPubKey);
                StorageMap kycAmlCertificationsCertificates = Storage.CurrentContext.CreateMap(nameof(kycAmlCertificationsCertificates));
                kycAmlCertificationsCertificates.Put(key, certificates);
            }
            return key;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns Failed! or the key of the KYC/AML certification given the public key of the
        ///     pseudonym KYC/AMLed, the KYC/AML certifier public key.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="passingKycAmlPseudonmyPubKey">
        ///     The public key of the pseudonym who has successfully passed KYC AML as byte[].
        /// </param>
        /// <param name="kycAmlCertifierPubKey">
        ///     The public of the KYC AML certifier who checked the KYC AML of the pseudonym as byte[].
        /// </param>
        ///
        /// <returns>   The key of the new KYC AML certification as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("passKycAmlWithoutCertificates")]
        public static byte[] PassKycAmlWithoutCertificates(byte[] passingKycAmlPseudonmyPubKey, byte[] kycAmlCertifierPubKey)
        {
            byte[] key = Failed;
            if (IsKycAmlCertifierPublicKey(kycAmlCertifierPubKey) && Runtime.CheckWitness(kycAmlCertifierPubKey))
            {
                Header header = Blockchain.GetHeader(Blockchain.GetHeight());
                uint timestamp = header.Timestamp;
                StorageMap timestamps = Storage.CurrentContext.CreateMap(nameof(timestamps));
                timestamps.Put(kycAmlCertifierPubKey, timestamp);
                byte[] timestampBytes = timestamps.Get(kycAmlCertifierPubKey);
                key = SmartContract.Sha256(passingKycAmlPseudonmyPubKey).Concat(Separator).Concat(SmartContract.Sha256(kycAmlCertifierPubKey)).
                    Concat(Separator).Concat(timestampBytes);
                Storage.Put(key, key);
                timestamps.Put(key, timestamp);
                StorageMap kycAmlCertificationsPubKeys = Storage.CurrentContext.CreateMap(nameof(kycAmlCertificationsPubKeys));
                kycAmlCertificationsPubKeys.Put(key, passingKycAmlPseudonmyPubKey);
                StorageMap kycAmlCertificationsCertifiers = Storage.CurrentContext.CreateMap(nameof(kycAmlCertificationsCertifiers));
                kycAmlCertificationsCertifiers.Put(key, kycAmlCertifierPubKey);
            }
            return key;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns Failed! or the key of the new information record given the public key of recorder.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="information">      The information to be recorded as byte[]. </param>
        /// <param name="pseudonymPubKey">  The public key of the recording pseudonym as byte[]. </param>
        ///
        /// <returns>   The key of the new record as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("recordWithoutSignature")]
        public static byte[] RecordWithoutSignature(byte[] information, byte[] pseudonymPubKey)
        {
            byte[] key = Failed;
            if (Runtime.CheckWitness(pseudonymPubKey))
            {
                Header header = Blockchain.GetHeader(Blockchain.GetHeight());
                uint timestamp = header.Timestamp;
                StorageMap timestamps = Storage.CurrentContext.CreateMap(nameof(timestamps));
                timestamps.Put(pseudonymPubKey, timestamp);
                byte[] timestampBytes = timestamps.Get(pseudonymPubKey);
                key = SmartContract.Sha256(information).Concat(Separator).Concat(SmartContract.Sha256(pseudonymPubKey)).
                    Concat(Separator).Concat(timestampBytes);
                StorageMap pseudonyms = Storage.CurrentContext.CreateMap(nameof(pseudonyms));
                pseudonyms.Put(key, pseudonymPubKey);
                StorageMap informations = Storage.CurrentContext.CreateMap(nameof(informations));
                informations.Put(key, information);
                timestamps.Put(key, timestamp);
                Storage.Put(key, key);
            }
            return key;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns Failed! or the key of the new information record given the public key of recorder
        ///     and a signature that will be recorded as well.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="information">      The information to be recorded as byte[]. </param>
        /// <param name="pseudonymPubKey">  The public key of the recording pseudonym as byte[]. </param>
        /// <param name="signature">
        ///     Signature of the message by the recording pseudonym as byte[].
        /// </param>
        ///
        /// <returns>   The key of the new record as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("recordWithSignature")]
        public static byte[] RecordWithSignature(byte[] information, byte[] pseudonymPubKey, byte[] signature)
        {
            byte[] key = Failed;
            if (Runtime.CheckWitness(pseudonymPubKey) && SmartContract.VerifySignature(information, signature, pseudonymPubKey))
            {
                key = RecordWithoutSignature(information, pseudonymPubKey);
                StorageMap signatures = Storage.CurrentContext.CreateMap(nameof(signatures));
                signatures.Put(key, signature);
            }
            return key;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns NotFound! or the information given the record key. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The record key as byte[]. </param>
        ///
        /// <returns>   The information of the record key as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveInformationByKey")]
        public static byte[] RetrieveInformationByKey(byte[] key)
        {
            byte[] information = NotFound;
            StorageMap informations = Storage.CurrentContext.CreateMap(nameof(informations));
            byte[] info = informations.Get(key);
            if (info.Length != 0)
            {
                information = info;
            }
            return information;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns NotFound! or the KYC/AML certification given the KYC/AML certification key.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The key of KYC AML certification as byte[]. </param>
        ///
        /// <returns>   The certificates as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveKycAmlCertificationCertificatesByKey")]
        public static byte[] RetrieveKycAmlCertificationCertificatesByKey(byte[] key)
        {
            byte[] certificates = NotFound;
            StorageMap kycAmlCertificationsCertificates = Storage.CurrentContext.CreateMap(nameof(kycAmlCertificationsCertificates));
            byte[] certs = kycAmlCertificationsCertificates.Get(key);
            if (certs.Length != 0)
            {
                certificates = certs;
            }
            return certificates;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns NotFound! or the KYC/AML certifier public key given the KYC/AML certification key.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The key of the AML KYC certification as byte[]. </param>
        ///
        /// <returns>   The certifier public key as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveKycAmlCertificationCertifierByKey")]
        public static byte[] RetrieveKycAmlCertificationCertifierByKey(byte[] key)
        {
            byte[] certifierPubKey = NotFound;
            StorageMap kycAmlCertificationsCertifiers = Storage.CurrentContext.CreateMap(nameof(kycAmlCertificationsCertifiers));
            byte[] certPubKey = kycAmlCertificationsCertifiers.Get(key);
            if (certPubKey.Length != 0)
            {
                certifierPubKey = certPubKey;
            }
            return certifierPubKey;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns NotFound! or the KYC/AML certification given a pseudonym public key and the
        ///     number of the certification to be retrieved since multiple KYC/AML certifications may
        ///     exist.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pubKey">   The KYC AMLed public key as byte[]. </param>
        /// <param name="number">
        ///     The number of the searched KYC AML certification of the given public key.
        /// </param>
        ///
        /// <returns>   The KYC AML certification key as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveKycAmlCertificationKeyByPubKeyAndNumber")]
        public static byte[] RetrieveKycAmlCertificationKeyByPubKeyAndNumber(byte[] pubKey, BigInteger number)
        {
            byte[] kycAmlKey = NotFound;
            Iterator<byte[], byte[]> records = Storage.Find(Storage.CurrentContext, SmartContract.Sha256(pubKey));
            for (int i = 0; records.Next() && i < number; i++)
            {
                kycAmlKey = records.Value;
            }
            return kycAmlKey;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns NotFound! or the pseudonym public key given the record key. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The key of the record. </param>
        ///
        /// <returns>   The pseudonym public key of the record as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrievePseudonymByKey")]
        public static byte[] RetrievePseudonymByKey(byte[] key)
        {
            byte[] pseudonym = NotFound;
            StorageMap pseudonyms = Storage.CurrentContext.CreateMap(nameof(pseudonyms));
            byte[] auth = pseudonyms.Get(key);
            if (auth.Length != 0)
            {
                pseudonym = auth;
            }
            return pseudonym;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Returns NotFound! or the record given the record key. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The full record given its key as byte[]. </param>
        ///
        /// <returns>   The full record as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveRecordByKey")]
        public static byte[] RetrieveRecordByKey(byte[] key)
        {
            byte[] record = NotFound;
            StorageMap timestamps = Storage.CurrentContext.CreateMap(nameof(timestamps));
            byte[] timestampBytes = timestamps.Get(key);
            if (timestampBytes.Length != 0)
            {
                StorageMap pseudonyms = Storage.CurrentContext.CreateMap(nameof(pseudonyms));
                byte[] pseudonymPubKey = pseudonyms.Get(key);
                StorageMap informations = Storage.CurrentContext.CreateMap(nameof(informations));
                byte[] information = informations.Get(key);
                StorageMap signatures = Storage.CurrentContext.CreateMap(nameof(signatures));
                byte[] signature = signatures.Get(key);
                if (signature.Length == 0)
                {
                    signature = NoSignature;
                }
                record = timestampBytes.Concat(Separator).Concat(pseudonymPubKey).Concat(Separator).Concat(signature).Concat(Separator).
                    Concat(information);
            }
            return record;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns NotFound! or the record key given the information and a number because the
        ///     information may have been recorded several times by different pseudonyms.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="information">  The searched information as byte[]. </param>
        /// <param name="number">       The record number of the searched information. </param>
        ///
        /// <returns>   The record key as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveRecordKeyByInformationAndNumber")]
        public static byte[] RetrieveRecordKeyByInformationAndNumber(byte[] information, BigInteger number)
        {
            byte[] key = NotFound;
            Iterator<byte[], byte[]> keys = Storage.Find(Storage.CurrentContext, SmartContract.Sha256(information));
            for (int i = 0; keys.Next() && i < number; i++)
            {
                key = keys.Value;
            }
            return key;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>
        ///     Returns NotFound! or the record key given a prefix and a number because the information
        ///     may have been recorded several times by different pseudonyms.
        /// </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="prefix">   The searched prefix as byte[]. </param>
        /// <param name="number">   The number of the record with such search prefix. </param>
        ///
        /// <returns>   The record key as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveRecordKeyByPrefixAndNumber")]
        public static byte[] RetrieveRecordKeyByPrefixAndNumber(byte[] prefix, BigInteger number)
        {
            byte[] key = NotFound;
            Iterator<byte[], byte[]> keys = Storage.Find(Storage.CurrentContext, prefix);
            for (int i = 0; keys.Next() && i < number; i++)
            {
                key = keys.Value;
            }
            return key;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Retrieves signature by key. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The record key as byte[]. </param>
        ///
        /// <returns>   The signature as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveSignatureByKey")]
        public static byte[] RetrieveSignatureByKey(byte[] key)
        {
            byte[] signature = NotFound;
            StorageMap signatures = Storage.CurrentContext.CreateMap(nameof(signatures));
            byte[] sig = signatures.Get(key);
            if (sig.Length != 0)
            {
                signature = sig;
            }
            return signature;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Retrieves timestamp by key. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="key">  The record key as byte[]. </param>
        ///
        /// <returns>   The timestamp as Unix time in Little Endian as byte[]. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("retrieveTimestampByKey")]
        public static byte[] RetrieveTimestampByKey(byte[] key)
        {
            byte[] timestamp = NotFound;
            StorageMap timestamps = Storage.CurrentContext.CreateMap(nameof(timestamps));
            byte[] tt = timestamps.Get(key);
            if (tt.Length != 0)
            {
                timestamp = tt;
            }
            return timestamp;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Revoke KYC AML certification by key. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="kycAmlCertificationKey">
        ///     The key of the KYC AML certification to be revoked as byte[].
        /// </param>
        /// <param name="kycAmlCertifierPubKey">
        ///     The public key of the KYC AML certifier willing to revoke the KYC AML certification as
        ///     byte[].
        /// </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("revokeKycAmlCertificationByKey")]
        public static bool RevokeKycAmlCertificationByKey(byte[] kycAmlCertificationKey, byte[] kycAmlCertifierPubKey)
        {
            bool revokedKycAml = false;
            if (Runtime.CheckWitness(kycAmlCertifierPubKey) &&
                ((IsKycAmlCertifierPublicKey(kycAmlCertifierPubKey) && RetrieveKycAmlCertificationCertifierByKey(kycAmlCertificationKey).Equals(kycAmlCertifierPubKey))
                    || IsCurrentCallerReputaction(kycAmlCertifierPubKey)))
            {
                Header header = Blockchain.GetHeader(Blockchain.GetHeight());
                uint timestamp = header.Timestamp;
                StorageMap revokedPubKeyKycAmlCertifications = Storage.CurrentContext.CreateMap(nameof(revokedPubKeyKycAmlCertifications));
                revokedPubKeyKycAmlCertifications.Put(kycAmlCertificationKey, timestamp);
            }
            return revokedKycAml;
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////
        /// <summary>   Sets a given pseudonym to alive. </summary>
        ///
        /// <remarks>   Dr Jean-Marc Seigneur, 7 May 2019. </remarks>
        ///
        /// <param name="pseudonymPubKey">  The public key of the pseudonym as byte[]. </param>
        ///
        /// <returns>   True if it succeeds, false if it fails. </returns>
        ////////////////////////////////////////////////////////////////////////////////////////////////////

        [DisplayName("setAlive")]
        public static bool SetAlive(byte[] pseudonymPubKey)
        {
            bool alive = false;
            if (Runtime.CheckWitness(pseudonymPubKey))
            {
                StorageMap alives = Storage.CurrentContext.CreateMap(nameof(alives));
                Header header = Blockchain.GetHeader(Blockchain.GetHeight());
                uint timestamp = header.Timestamp;
                byte[] timestampBytes = alives.Get(pseudonymPubKey);
                if (timestampBytes.Length == 0)
                {
                    alives.Put(pseudonymPubKey, timestamp);
                }
                alive = true;
            }
            return alive;
        }
    }
}