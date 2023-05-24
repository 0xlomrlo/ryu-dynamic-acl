import json
import conf
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route


class DynamicACLController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(DynamicACLController, self).__init__(req, link, data, **config)
        self.app = data[conf.INSTANCE_NAME]

    @route('dump_info', f"{conf.URL_PREFIX}/info", methods=['GET'])
    def dump_info(self, req, **kwargs):
        dp_list = []

        for dp in self.app.dpset.get_all():
            dpobj = dp[1]
            dp_devices = {}
            if dpobj.id in self.app.mac_to_port:
                dp_devices = self.app.mac_to_port[dpobj.id]

            dp_list.append({"id": dpobj.id, "devices": dp_devices})

        data = {
            "datapath_list": dp_list,
            "protected_mac_list": list(self.app.protected_mac_list)
        }
        body = json.dumps(data)

        return Response(content_type='application/json', text=body)

    @route('add_protected_srv', f"{conf.URL_PREFIX}/srv", methods=['POST'])
    def add_protected_srv(self, req, **kwargs):
        try:
            req_data = req.json if req.body else {}
            if "mac_address" in req_data:
                self.app._add_protected_device(req_data["mac_address"])
        except ValueError:
            data = {"operation_status": "failed", "reason": "bad request"}
            return Response(status=400, content_type='application/json', text=json.dumps(data))

        data = {"operation_status": "success"}

        return Response(content_type='application/json', text=json.dumps(data))

    @route('del_protected_srv', f"{conf.URL_PREFIX}/srv", methods=['DELETE'])
    def del_protected_srv(self, req, **kwargs):
        try:
            req_data = req.json if req.body else {}
            if "mac_address" in req_data:
                self.app._remove_protected_device(req_data["mac_address"])
        except ValueError:
            data = {"operation_status": "failed", "reason": "bad request"}
            return Response(status=400, content_type='application/json', text=json.dumps(data))

        data = {"operation_status": "success"}

        return Response(content_type='application/json', text=json.dumps(data))
