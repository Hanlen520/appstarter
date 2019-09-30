Java.perform(function () {
    //小米5权限弹框进程：com.lbe.security.miui:ui
    //原理：在拦截弹框启动函数，直接调用回调函数
    var flag = true
    var count = 0
    var ps = ''
    var GrantPermissionsActivity = Java.use('com.android.packageinstaller.permission.ui.GrantPermissionsActivity');
    GrantPermissionsActivity.showNextPermissionGroupGrantRequest.overload().implementation = function(){
        if(flag){
            flag = false
            var clazz = Java.use("java.lang.Class");
            var param = Java.cast(this.getClass(), clazz).getDeclaredField("mRequestGrantPermissionGroups");
            param.setAccessible(true);
            ps = param.get(this).toString()
            ps = ps.replace('{', '').replace('}', '').split(', ')
            count = ps.length-1
        }
        
        if (count>=0){
            var p = ps[count--].split('=')[0]
            console.log(p)
            this.onPermissionGrantResult(p, true, false)
            return true
        }else{
            flag = true
            ps = ''
            return false
        }
    }
})
