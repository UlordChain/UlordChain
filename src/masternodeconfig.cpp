
#include "netbase.h"
#include "masternodeconfig.h"
#include "util.h"
#include "chainparams.h"

#include "coins.h"
#include "main.h"


#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

CMasternodeConfig masternodeConfig;

void CMasternodeConfig::add(std::string alias, std::string ip, std::string privKey, std::string txHash, std::string outputIndex) {
    CMasternodeEntry cme(alias, ip, privKey, txHash, outputIndex);
    entries.push_back(cme);
}

bool CMasternodeConfig::read(std::string& strErr) {


    int64_t masternodecout = GetArg("-masternode", 0);  
    if(masternodecout)
    {
        std::string alias, ip, privKey, txHash, outputIndex;
        alias = GetArg("-alias", "mnl");
        if(alias.empty())
        {
            strErr = _("please add your masternode name into ulord.conf; for example: alias=mynode\n");
        }
        ip = GetArg("-externalip", "");
        if(ip.empty())
        {
            strErr = _("Invalid masternode ip, please add your ip into ulord.conf; for example: externalip=0.0.0.0\n");
            return false;
        }
        ip = ip + ":" + std::to_string(Params().GetDefaultPort());
        
        privKey = GetArg("-masternodeprivkey", "");
        if(privKey.empty())
        {
            strErr = _("Invalid masternode privKey, please add your privKey into ulord.conf; for example: masternodeprivkey=***\n");
            return false;
        }
        txHash = GetArg("-collateraloutputtxid", "");
        if(txHash.empty())
        {
            strErr = _("Invalid masternode collateral txid, please add your collateral txid into ulord.conf; for example: collateraloutputtxid=***\n");
            return false;
        }

        outputIndex = GetArg("-collateraloutputindex", "");
        if(outputIndex.empty())
        {
            strErr = _("Invalid masternode collateral Index, please add your collateral Index into ulord.conf; for example: collateraloutputindex=0\n");
            return false;
        }
        
        int port = 0;
        std::string hostname = "";
        SplitHostPort(ip, port, hostname);
        if(port == 0 || hostname == "") {
            strErr = _("Failed to parse host:port string") + "\n";
            return false;
        }
        int mainnetDefaultPort = Params(CBaseChainParams::MAIN).GetDefaultPort();
        if(Params().NetworkIDString() == CBaseChainParams::MAIN) {
            if(port != mainnetDefaultPort) {
                strErr = _("Invalid port detected in ulord.conf") + "\n" +
                        strprintf(_("Port: %d"), port) + "\n" +
                        strprintf(_("(must be %d for mainnet)"), mainnetDefaultPort);
                return false;
            }
        } else if(port == mainnetDefaultPort) {
            strErr = _("Invalid port detected in ulord.conf") + "\n" +
                    strprintf(_("(%d could be used only on mainnet)"), mainnetDefaultPort);
            return false;
        }
            
        add(alias, ip, privKey, txHash, outputIndex);
    }
    return true;
}

CMasternodeConfig::CMasternodeEntry CMasternodeConfig::GetLocalEntry()
{
	if(fMasterNode)
	{
		for(auto & mn : entries)
		{
			if(mn.getPrivKey() == GetArg("-masternodeprivkey", ""))
				return mn;
		}
	}
	return CMasternodeEntry();
}

bool CMasternodeConfig::IsLocalEntry()
{
	if(fMasterNode)
	{
		for(auto & mn : entries)
		{
			if(mn.getPrivKey() == GetArg("-masternodeprivkey", "") && GetArg("-collateraloutputtxid", "") != "" 
				&& GetArg("-broadcastsign", "") != "")
				return true;
		}
	}
	return false;
}

bool CMasternodeConfig::GetMasternodeVin(CTxIn& txinRet,  std::string strTxHash, std::string strOutputIndex)
{
    // wait for reindex and/or import to finish
    if (fImporting || fReindex) return false;


    if(strTxHash.empty()) // No output specified, select the one specified by masternodeConfig
    {
        if(masternodeConfig.IsLocalEntry())
        {
            CMasternodeConfig::CMasternodeEntry mne = masternodeConfig.GetLocalEntry();
            unsigned int index = atoi(mne.getOutputIndex().c_str());
            uint256 txHash = uint256S(mne.getTxHash());
            txinRet = CTxIn(txHash, index);
            CCoins coins;
            if(!pcoinsTip->GetCoins(txHash, coins) || index >=coins.vout.size() || coins.vout[index].IsNull())
            {
                LogPrintf("CMasternodeBroadcast::getPubKeyId -- masternode collateraloutputtxid or collateraloutputindex is error,please check it\n");
                return false;
            }
            return true;
        }
        LogPrintf("CMasternodeConfig::GetMasternodeVin -- Could not locate the masternode configure vin, please check the ulord.conf\n");
        return false;
    }

    // Find specific vin
    uint256 txHash = uint256S(strTxHash);
    int nOutputIndex = atoi(strOutputIndex.c_str());

    txinRet = CTxIn(txHash,nOutputIndex);
    CCoins coins;
    if(pcoinsTip->GetCoins(txHash, coins))	
    {
        return true;
    }
    
    LogPrintf("CMasternodeConfig::GetMasternodeVin -- Could not locate specified masternode vin\n");
    return false;    
}
