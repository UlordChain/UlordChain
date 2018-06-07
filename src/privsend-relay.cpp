#include "privsend.h"
#include "privsend-relay.h"


CPrivSendRelay::CPrivSendRelay()
{
    vinMasternode = CTxIn();
    nBlockHeight = 0;
    nRelayType = 0;
    in = CTxIn();
    out = CTxOut();
}

CPrivSendRelay::CPrivSendRelay(CTxIn& vinMasternodeIn, vector<unsigned char>& vchSigIn, int nBlockHeightIn, int nRelayTypeIn, CTxIn& in2, CTxOut& out2)
{
    vinMasternode = vinMasternodeIn;
    vchSig = vchSigIn;
    nBlockHeight = nBlockHeightIn;
    nRelayType = nRelayTypeIn;
    in = in2;
    out = out2;
}

std::string CPrivSendRelay::ToString()
{
    std::ostringstream info;

    info << "vin: " << vinMasternode.ToString() <<
        " nBlockHeight: " << (int)nBlockHeight <<
        " nRelayType: "  << (int)nRelayType <<
        " in " << in.ToString() <<
        " out " << out.ToString();
        
    return info.str();   
}

bool CPrivSendRelay::Sign(std::string strSharedKey)
{
    std::string strError = "";
    std::string strMessage = in.ToString() + out.ToString();

    CKey key2;
    CPubKey pubkey2;

    if(!privSendSigner.GetKeysFromSecret(strSharedKey, key2, pubkey2)) {
        LogPrintf("CPrivSendRelay::Sign -- GetKeysFromSecret() failed, invalid shared key %s\n", strSharedKey);
        return false;
    }

    if(!privSendSigner.SignMessage(strMessage, vchSig2, key2)) {
        LogPrintf("CPrivSendRelay::Sign -- SignMessage() failed\n");
        return false;
    }

    if(!privSendSigner.VerifyMessage(pubkey2, vchSig2, strMessage, strError)) {
        LogPrintf("CPrivSendRelay::Sign -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

bool CPrivSendRelay::VerifyMessage(std::string strSharedKey)
{
    std::string strError = "";
    std::string strMessage = in.ToString() + out.ToString();

    CKey key2;
    CPubKey pubkey2;

    if(!privSendSigner.GetKeysFromSecret(strSharedKey, key2, pubkey2)) {
        LogPrintf("CPrivSendRelay::VerifyMessage -- GetKeysFromSecret() failed, invalid shared key %s\n", strSharedKey);
        return false;
    }

    if(!privSendSigner.VerifyMessage(pubkey2, vchSig2, strMessage, strError)) {
        LogPrintf("CPrivSendRelay::VerifyMessage -- VerifyMessage() failed, error: %s\n", strError);
        return false;
    }

    return true;
}

void CPrivSendRelay::Relay()
{
    int nCount = std::min(mnodeman.CountEnabled(MIN_PRIVATESEND_PEER_PROTO_VERSION), 20);
    int nRank1 = (rand() % nCount)+1; 
    int nRank2 = (rand() % nCount)+1; 

    //keep picking another second number till we get one that doesn't match
    while(nRank1 == nRank2) nRank2 = (rand() % nCount)+1;

    //printf("rank 1 - rank2 %d %d \n", nRank1, nRank2);

    //relay this message through 2 separate nodes for redundancy
    RelayThroughNode(nRank1);
    RelayThroughNode(nRank2);
}

void CPrivSendRelay::RelayThroughNode(int nRank)
{
    CMasternode* pmn = mnodeman.GetMasternodeByRank(nRank, nBlockHeight, MIN_PRIVATESEND_PEER_PROTO_VERSION);

    if(pmn != NULL){
        //printf("RelayThroughNode %s\n", pmn->addr.ToString().c_str());
        CNode* pnode = ConnectNode((CAddress)pmn->addr, NULL);
        if(pnode) {
            //printf("Connected\n");
            pnode->PushMessage("dsr", (*this));
            return;
        }
    } else {
        //printf("RelayThroughNode NULL\n");
    }
}
