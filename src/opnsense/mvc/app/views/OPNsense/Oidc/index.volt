<div class="content-box" style="padding-bottom: 1.5em;">
    {{ partial("layout_partials/base_form",['fields':generalForm,'id':'frm_general_settings'])}}

    <div class="col-md-12">
        <hr />
        <div class="alert alert-info">
            <strong>OIDC Redirect URI:</strong><br />
            Configure your OIDC provider with this redirect URI:<br />
            <code>{{ redirectUri }}</code>
        </div>
    </div>

    <div class="col-md-12">
        <button class="btn btn-primary" id="saveAct" type="button">
            <b>{{ lang._('Save') }}</b> <i id="saveAct_progress"></i>
        </button>
        <button class="btn btn-default" id="testAct" type="button">
            <b>{{ lang._('Test OIDC') }}</b> <i id="testAct_progress"></i>
        </button>
    </div>
</div>

<script>
    $(document).ready(function () {
        var data_get_map = {
            'frm_general_settings': "/api/oidc/get"
        };
        mapDataToFormUI(data_get_map).done(function (data) {
            formatTokenizersUI();
            $('.selectpicker').selectpicker('refresh');
        });

        $("#saveAct").click(function () {
            saveFormToEndpoint(url = "/api/oidc/set", formid = 'frm_general_settings', callback_ok = function () {
                $("#saveAct_progress").removeClass("fa fa-spinner fa-pulse");
            });
        });

        $("#testAct").click(function () {
            $("#testAct_progress").addClass("fa fa-spinner fa-pulse");
            ajaxCall(url = "/api/oidc/auth", sendData = {}, callback = function (data, status) {
                $("#testAct_progress").removeClass("fa fa-spinner fa-pulse");
                if (data.status === 'redirect') {
                    window.open(data.url, '_blank');
                } else if (data.error) {
                    BootstrapDialog.alert('Test failed: ' + data.error);
                }
            });
        });
    });
</script>