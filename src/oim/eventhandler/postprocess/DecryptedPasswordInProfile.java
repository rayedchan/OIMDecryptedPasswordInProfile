package oim.eventhandler.postprocess;

import com.thortech.xl.crypto.tcCryptoException;
import com.thortech.xl.crypto.tcCryptoUtil;
import java.io.Serializable;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;
import oracle.core.ojdl.logging.ODLLogger;
import oracle.iam.identity.exception.NoSuchUserException;
import oracle.iam.identity.exception.SearchKeyNotUniqueException;
import oracle.iam.identity.exception.UserModifyException;
import oracle.iam.identity.exception.ValidationFailedException;
import oracle.iam.identity.usermgmt.api.UserManager;
import oracle.iam.identity.usermgmt.vo.User;
import oracle.iam.platform.Platform;
import oracle.iam.platform.authz.exception.AccessDeniedException;
import oracle.iam.platform.context.ContextAware;
import oracle.iam.platform.kernel.spi.PostProcessHandler;
import oracle.iam.platform.kernel.vo.AbstractGenericOrchestration;
import oracle.iam.platform.kernel.vo.BulkEventResult;
import oracle.iam.platform.kernel.vo.BulkOrchestration;
import oracle.iam.platform.kernel.vo.EventResult;
import oracle.iam.platform.kernel.vo.Orchestration;

/**
 * @author rayedchan
 * Event Handler Type: Post-Process
 * Triggers: Whenever a password is changed as defined
 * in the meta-data XML file (operation="CHANGE_PASSWORD") for this event handler.
 * Action: Set the previous and current password to be values
 * for selected OIM User attributes.
 * 
 * Note: This should never be done in practice. This
 * is only meant for a learning tutorial about event handlers.
 */
public class DecryptedPasswordInProfile implements PostProcessHandler
{
    //ODL Logger, which OIM uses by default
    //ojdl.jar can be found in MIDDLEWAREHOME/oracle_common/modules/oracle.odl_11.1.1
    public static final Logger logger = ODLLogger.getLogger(DecryptedPasswordInProfile.class.getName());
    
    /**
     * @param processId     OIM.ORCHEVENTS.ProcessId
     * @param eventId       OIM.ORCHEVENTS.ID
     * @param orchestration Holds useful data
     */
    @Override
    public EventResult execute(long processId, long eventId, Orchestration orchestration) 
    {
        logger.info("Start DecryptedPasswordInProfile execute method 2.0: ");
        try
        {
            logger.info(String.format("Start execute() with ProcessId: %s and EventId %s",processId, eventId));
            HashMap<String, Serializable> newParameters = orchestration.getParameters(); //contains only the new values
            HashMap<String, Serializable> interParameters = orchestration.getInterEventData(); //contains old and new values of user
            logger.info(String.format("Inter Parameters: %s ", interParameters));
            logger.info(String.format("New Parameters: %s ", newParameters));
        
            //Check if the user's password is being modified
            //If it is, it should be in the newParameters object
            if(newParameters.get("usr_password") != null)
            {
                User currentUserState = (User) interParameters.get("CURRENT_USER"); //Get target user's current (old) info state
                String userKey = orchestration.getTarget().getEntityId(); //Get the target user's key
                String userLogin = currentUserState.getLogin(); //Get target user's login
                
                //ContextAware object is present when a user is changing his or password.
                //When an actor is present typically an administrator, the parameter is a String Object.  
                String oldPasswordEncrypted = (currentUserState.getAttribute("usr_password") instanceof ContextAware)
                    ? (String) ((ContextAware) currentUserState.getAttribute("usr_password")).getObjectValue()
                    : (String) currentUserState.getAttribute("usr_password");
                
                //Decrypt password using the default secret key
                String oldPasswordDecrypted = tcCryptoUtil.decrypt(oldPasswordEncrypted, "DBSecretKey"); 
                String newPasswordEncrypted = getParamaterValue(newParameters, "usr_password"); 
                String newPasswordDecrypted = tcCryptoUtil.decrypt(newPasswordEncrypted, "DBSecretKey");
                
                logger.info(String.format("User's password is being changed. User Key: %s, Login: %s", userKey, userLogin));
                logger.info(String.format("Old Password: %s\nNew Password: %s\n", oldPasswordDecrypted, newPasswordDecrypted));
                
                UserManager usrOps = Platform.getService(UserManager.class); //Get services from UserManager class
                HashMap modParams = new HashMap(); //contains the attaributes to modify
                modParams.put("State", oldPasswordDecrypted); //set State attribute value to old password 
                modParams.put("Street", newPasswordDecrypted); //set Street attrinute value to new passord
                User modUser = new User(userKey, modParams);
                usrOps.modify("usr_key", userKey, modUser); //modify the target user
                logger.info("User is modified.");
            }
        } 
        
        catch (ValidationFailedException ex) {logger.log(Level.SEVERE,"",ex);}
        catch (AccessDeniedException ex) {logger.log(Level.SEVERE,"",ex);}
        catch (UserModifyException ex) {logger.log(Level.SEVERE,"",ex);} 
        catch (NoSuchUserException ex) {logger.log(Level.SEVERE,"",ex);}
        catch (SearchKeyNotUniqueException ex) {logger.log(Level.SEVERE,"",ex);}
        catch (tcCryptoException ex) {logger.log(Level.SEVERE,"",ex);}
        catch (Exception ex) {logger.log(Level.SEVERE,"",ex);}

        return new EventResult();
    }
    
    /**
     * ContextAware object is obtained when the user is changing his or her own password.
     * If an actor is present such as an administrator, the exact value of the attribute is obtained.
     * @param parameters    parameters from the orchestration object
     * @param key   name of User Attribute in OIM Profile or column in USR table
     * @return value of the corresponding key in parameters
     */
    private String getParamaterValue(HashMap<String, Serializable> parameters, String key) 
    {
        String value = (parameters.get(key) instanceof ContextAware)
        ? (String) ((ContextAware) parameters.get(key)).getObjectValue()
        : (String) parameters.get(key);
        return value;
    }
    

    @Override
    public BulkEventResult execute(long l, long l1, BulkOrchestration bo) 
    {
        return null;
    }

    @Override
    public void compensate(long l, long l1, AbstractGenericOrchestration ago) 
    {
        
    }

    @Override
    public boolean cancel(long l, long l1, AbstractGenericOrchestration ago) 
    {
        return false;
    }

    @Override
    public void initialize(HashMap<String, String> hm) 
    {
       
    }
}
