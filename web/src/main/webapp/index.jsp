<%@ page import="ru.iriyc.cc.server.service.WebService" %>
<%--<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>--%>
<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <title>Upload</title>
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"
            type="application/javascript"></script>
    <script type="application/javascript">
        $(document).ready(function () {
            $("#logout").click(function () {
                $.post('<%=request.getContextPath()%>/rest/me/logout', function () {
                    window.location = '<%=request.getContextPath()%>'
                })
            })
        })
    </script>
</head>


<body>
<%
    String username = WebService.INSTANCE.loggedUser(request);
    if (username == null) {
%>
<form action="<%=request.getContextPath()%>/rest/login" method="POST">
    <fieldset>
        <input name="username" type="text" title="Username"> <br>
        <input name="password" type="password" title="Password"> <br>
    </fieldset>
    <button type="submit">Войти</button>
</form>
<%
} else {
%>
Пользователь: <%=username%> <br>

<button id="logout" type="submit">Выйти</button>
<%
    }
%>

</body>

</html>
