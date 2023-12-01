package fit.se.week8.record;

public record UserInfo(String userName, String password, boolean enable, String []
        authorities){
}